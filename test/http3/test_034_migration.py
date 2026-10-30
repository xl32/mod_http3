import os
import socket
import sys
import time

import pytest

from aioquic.quic import events as quic_events

from .env import H3Conf
from .test_033_paths import _Client

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="SO_REUSEPORT buckets are Linux only")


def _migrate(c):
    """Send from a new local port: a new 4-tuple, so a new kernel hash."""
    old = c.sock
    c.sock = socket.socket(old.family, socket.SOCK_DGRAM)
    c.sock.connect(c.target)
    c.sock.settimeout(0.05)
    old.close()


def _ping(c, uid, seconds=2):
    c.events.clear()
    c.quic.send_ping(uid)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        c.run(0.1, until_done=False)
        if any(isinstance(e, quic_events.PingAcknowledged) and e.uid == uid for e in c.events):
            return True
        if any(isinstance(e, quic_events.ConnectionTerminated) for e in c.events):
            return False
    return False


class TestRouting:
    """An eBPF program routes each packet to the bucket in byte 0 of its connection ID, so migration works."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        cpus = os.cpu_count() or 1
        if cpus < 2:
            pytest.skip("two buckets need two cores")
        H3Conf(env).add(f"ListenCoresBucketsRatio {cpus // 2}").add_vhost_test1().install()
        assert env.apache_restart() == 0

    def _client(self, env):
        c = _Client(env, "127.0.0.1")
        assert c.handshake()
        # H3_MIGRATE_ANYWAY=1: migrate also when routing is off (negative control).
        if c.quic.server_params.disable_active_migration and not os.environ.get("H3_MIGRATE_ANYWAY"):
            c.close()
            pytest.skip("routing by connection ID is off here (old kernel, no CAP_BPF, SELinux or seccomp)")
        return c

    def test_001_server_cids_carry_one_bucket(self, env):
        c = self._client(env)
        c.run(0.5, until_done=False)  # NEW_CONNECTION_ID frames follow the handshake
        cids = [c.quic._peer_cid.cid] + [p.cid for p in c.quic._peer_cid_available]
        assert len(cids) > 1, "the server issued no new connection IDs"
        assert len({cid[0] for cid in cids}) == 1, [cid.hex() for cid in cids]
        c.close()

    def test_002_connection_survives_migration(self, env):
        c = self._client(env)
        # A client may migrate only after the handshake is confirmed (RFC 9000 9): HANDSHAKE_DONE has come once a ping is acked.
        assert _ping(c, 100), "no ack before migration"
        for i in range(6):
            _migrate(c)
            if i == 5:
                c.quic.change_connection_id()  # a CID from NEW_CONNECTION_ID
            assert _ping(c, i), f"migration {i + 1}: no answer, the packet reached another child"
        c.close()
