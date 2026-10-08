import os
import sys
import time

import pytest

from .env import H3Conf

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the parent binds the QUIC socket on Linux only")


def _udp_inodes(port):
    """Socket inodes bound to UDP port, from /proc/net/udp and udp6."""
    found = set()
    for name in ("udp", "udp6"):
        with open(f"/proc/net/{name}") as fd:
            for line in fd.readlines()[1:]:
                cols = line.split()
                if int(cols[1].rsplit(":", 1)[1], 16) == port:
                    found.add(cols[9])
    return found


def _socket_inodes(pid):
    inodes = set()
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            link = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if link.startswith("socket:["):
            inodes.add(link[8:-1])
    return inodes


def _parent_pid(env):
    """A relative PidFile resolves against the runtime dir: ServerRoot or logs/, by build."""
    for path in (os.path.join(env.server_dir, "httpd.pid"), os.path.join(env.server_dir, "logs", "httpd.pid")):
        if os.path.exists(path):
            with open(path) as fd:
                return int(fd.read().strip())
    raise FileNotFoundError("httpd.pid")


class TestParentSocket:
    """The parent binds the QUIC socket before it drops privileges, so ports below 1024 work."""

    def test_001_parent_holds_the_quic_socket(self, env):
        H3Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0
        parent = _parent_pid(env)
        bound = _udp_inodes(env.https_port)
        assert bound, "nothing is bound to the QUIC port"
        assert bound & _socket_inodes(parent), "the parent does not hold the QUIC socket"

    def test_002_socket_survives_a_graceful_restart(self, env):
        """The same socket stays bound across a graceful restart, so the port is never released."""
        H3Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0
        before = _udp_inodes(env.https_port)
        assert env.apache_reload() == 0
        assert before & _udp_inodes(env.https_port), "a graceful restart rebound the QUIC socket"
        r = env.curl_get(env.mkurl("https", "test1", "/"), options=["--http3-only", "-k"])
        assert r.exit_code == 0, r.stderr

    def test_003_one_socket_per_listener_bucket(self, env):
        """With ListenCoresBucketsRatio, the parent binds one SO_REUSEPORT socket per bucket and one child serves each."""
        cpus = os.cpu_count() or 1
        if cpus < 2:
            pytest.skip("two buckets need two cores")
        ratio = cpus // 2
        buckets = cpus // ratio
        H3Conf(env).add(f"ListenCoresBucketsRatio {ratio}").add_vhost_test1().install()
        assert env.apache_restart() == 0
        parent = _parent_pid(env)
        assert len(_udp_inodes(env.https_port) & _socket_inodes(parent)) == buckets
        want = {f"@mod_http3.{env.https_port}.{i}" for i in range(buckets)}
        for _ in range(50):
            with open("/proc/net/unix") as fd:
                owned = {line.split()[-1] for line in fd.readlines()[1:]}
            if want <= owned:
                break
            time.sleep(0.1)
        assert want <= owned, f"buckets without a child: {sorted(want - owned)}"
        r = env.curl_get(env.mkurl("https", "test1", "/"), options=["--http3-only", "-k"])
        assert r.exit_code == 0, r.stderr
