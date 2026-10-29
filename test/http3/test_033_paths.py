import os
import socket
import ssl
import sys
import time

import pytest

from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN
from aioquic.quic import events as quic_events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import pull_quic_transport_parameters

from .env import H3Conf

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="source address and ECN handling is Linux only")

IP_TOS = 1
IP_RECVTOS = 13
IPV6_RECVTCLASS = 66
IPV6_TCLASS = 67
ECT0 = 2


class _Conn(QuicConnection):
    """Keeps the server transport parameters and the ACK frame types it sends."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server_params = None
        self.ack_types = set()

    def _parse_transport_parameters(self, data, from_session_ticket=False):
        if not from_session_ticket:
            self.server_params = pull_quic_transport_parameters(Buffer(data=data))
        return super()._parse_transport_parameters(data, from_session_ticket)

    def _handle_ack_frame(self, context, frame_type, buf):
        self.ack_types.add(frame_type)
        return super()._handle_ack_frame(context, frame_type, buf)


def _ecn(level, kind, data):
    if (level, kind) == (socket.IPPROTO_IP, IP_TOS):
        return data[0] & 3
    if (level, kind) == (socket.IPPROTO_IPV6, IPV6_TCLASS):
        return int.from_bytes(data[:4], sys.byteorder) & 3
    return None


class _Client:
    """A QUIC client on a connected UDP socket: the kernel drops a reply from any other address."""

    def __init__(self, env, host, tos=0):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.target = (host, env.https_port)
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.connect(self.target)
        if family == socket.AF_INET:
            self.sock.setsockopt(socket.IPPROTO_IP, IP_RECVTOS, 1)
            self.sock.setsockopt(socket.IPPROTO_IP, IP_TOS, tos)
        else:
            self.sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVTCLASS, 1)
            self.sock.setsockopt(socket.IPPROTO_IPV6, IPV6_TCLASS, tos)
        self.sock.settimeout(0.05)
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE, server_name=f"test1.{env.http_tld}")
        self.quic = _Conn(configuration=config)
        self.ecn_in = []
        self.done = False

    def run(self, seconds, until_done=True):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not (until_done and self.done):
            now = time.monotonic()
            for data, _ in self.quic.datagrams_to_send(now=now):
                self.sock.send(data)
            try:
                data, anc, _, _ = self.sock.recvmsg(65535, socket.CMSG_SPACE(4) * 2)
            except (TimeoutError, socket.timeout):
                timer = self.quic.get_timer()
                if timer is not None and timer <= time.monotonic():
                    self.quic.handle_timer(now=time.monotonic())
                continue
            self.ecn_in += [e for e in (_ecn(*c) for c in anc) if e is not None]
            self.quic.receive_datagram(data, self.target, now=time.monotonic())
            while (event := self.quic.next_event()) is not None:
                if isinstance(event, quic_events.HandshakeCompleted):
                    self.done = True
        return self.done

    def handshake(self, seconds=5):
        self.quic.connect(self.target, now=time.monotonic())
        return self.run(seconds)

    def close(self):
        self.quic.close()
        self.run(0.2, until_done=False)
        self.sock.close()


def _v6_loopback():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


class TestSourceAddress:
    """The [::] socket replies from the address each packet came to (IP_PKTINFO / IPV6_PKTINFO)."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        H3Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0

    def test_001_second_ipv4_address(self, env):
        """127.0.0.2 is local too; a reply from 127.0.0.1 never reaches a connected client."""
        c = _Client(env, "127.0.0.2")
        assert c.handshake(), "no handshake on 127.0.0.2: the reply came from the wrong address"
        c.close()

    def test_002_first_ipv4_address(self, env):
        c = _Client(env, "127.0.0.1")
        assert c.handshake()
        c.close()

    def test_003_ipv6_loopback(self, env):
        if not _v6_loopback():
            pytest.skip("no ::1 in this host")
        c = _Client(env, "::1")
        assert c.handshake()
        c.close()

    def test_004_curl_on_the_second_address(self, env):
        url = env.mkurl("https", "test1", "/")
        r = env.curl_get(url, options=["--http3-only", "-k", "--resolve", f"test1.{env.http_tld}:{env.https_port}:127.0.0.2"])
        assert r.exit_code == 0, r.stderr


class TestEcn:
    """ECN marks come in through IP_RECVTOS / IPV6_RECVTCLASS and go out on the socket."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        H3Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
    def test_001_server_reports_the_marks_it_got(self, env, host):
        """A client that sends ECT(0) gets ACK_ECN frames (type 0x03) back."""
        if ":" in host and not _v6_loopback():
            pytest.skip("no ::1 in this host")
        c = _Client(env, host, tos=ECT0)
        assert c.handshake()
        for _ in range(5):
            c.quic.send_ping(0)
            c.run(0.1, until_done=False)
        assert 0x03 in c.quic.ack_types, f"no ACK_ECN, ACK types seen: {sorted(c.quic.ack_types)}"
        c.close()

    @pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
    def test_002_server_marks_its_packets(self, env, host):
        """ngtcp2 tests the path with ECT(0); the mark must reach the wire."""
        if ":" in host and not _v6_loopback():
            pytest.skip("no ::1 in this host")
        c = _Client(env, host)
        assert c.handshake()
        for _ in range(5):
            c.quic.send_ping(0)
            c.run(0.1, until_done=False)
        assert any(e in (1, 2) for e in c.ecn_in), f"no ECT mark on {len(c.ecn_in)} packets"
        c.close()


class TestMigration:
    """disable_active_migration goes out only when more than one SO_REUSEPORT socket serves the port."""

    def _params(self, env):
        c = _Client(env, "127.0.0.1")
        assert c.handshake()
        params = c.quic.server_params
        c.close()
        return params

    def test_001_one_socket_allows_migration(self, env):
        H3Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0
        assert not self._params(env).disable_active_migration

    def test_002_buckets_disable_migration(self, env):
        cpus = os.cpu_count() or 1
        if cpus < 2:
            pytest.skip("two buckets need two cores")
        H3Conf(env).add(f"ListenCoresBucketsRatio {cpus // 2}").add_vhost_test1().install()
        assert env.apache_restart() == 0
        assert self._params(env).disable_active_migration


def _children(env):
    from .test_032_parent_socket import _parent_pid

    parent = _parent_pid(env)
    with open(f"/proc/{parent}/task/{parent}/children") as fd:
        return {int(p) for p in fd.read().split()}


def _is_retry(datagram):
    return len(datagram) >= 5 and datagram[0] & 0xC0 == 0xC0 and (datagram[0] >> 4) & 0x03 == 0x03


class TestRetrySecret:
    """The parent keeps the token key: a Retry token from one child generation is good in the next."""

    def test_001_token_survives_a_graceful_restart(self, env):
        H3Conf(env).add_vhost_test1(h3_address_validation=True).install()
        assert env.apache_restart() == 0
        c = _Client(env, "127.0.0.1")
        c.quic.connect(c.target, now=time.monotonic())
        retry = None
        for data, _ in c.quic.datagrams_to_send(now=time.monotonic()):
            c.sock.send(data)
        deadline = time.monotonic() + 2
        while retry is None and time.monotonic() < deadline:
            try:
                data = c.sock.recv(65535)
            except (TimeoutError, socket.timeout):
                continue
            retry = data if _is_retry(data) else None
        assert retry, "no Retry from the server"
        c.quic.receive_datagram(retry, c.target, now=time.monotonic())
        with_token = [d for d, _ in c.quic.datagrams_to_send(now=time.monotonic())]
        assert with_token

        old = _children(env)
        assert env.apache_reload() == 0
        deadline = time.monotonic() + 8
        while old & _children(env) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not old & _children(env), "the old children did not stop"

        # The token lives 10 s. A child with its own key answers with a second Retry.
        answer = None
        deadline = time.monotonic() + 3
        while answer is None and time.monotonic() < deadline:
            for d in with_token:
                c.sock.send(d)
            try:
                answer = c.sock.recv(65535)
            except (TimeoutError, socket.timeout):
                continue
        assert answer is not None, "no answer from the new child"
        assert not _is_retry(answer), "the new child refused a token from the old one"
        c.sock.close()
