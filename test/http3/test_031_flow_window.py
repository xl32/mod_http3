import asyncio
import ssl

import pytest

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

from .env import H3Conf

INITIAL_WINDOW = 1024 * 1024
UPLOAD = 8 * 1024 * 1024
DELAY = 0.025  # a real RTT: ngtcp2 autotunes only when the window fills within a few RTTs


class _SlowUploader(QuicConnectionProtocol):
    """Delays every datagram it sends, and waits for the response headers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.done = asyncio.get_running_loop().create_future()

    def connection_made(self, transport):
        loop = asyncio.get_running_loop()

        class _Delayed:
            def sendto(self, data, addr=None):
                loop.call_later(DELAY, transport.sendto, data, addr)

            def __getattr__(self, name):
                return getattr(transport, name)

        super().connection_made(_Delayed())

    def quic_event_received(self, event):
        for h3_event in self.h3.handle_event(event):
            if isinstance(h3_event, HeadersReceived) and not self.done.done():
                self.done.set_result(True)


def _upload_credit(env):
    """Upload UPLOAD bytes; return the connection credit the server still grants afterwards."""
    authority = f"test1.{env.http_tld}"

    async def run():
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                   verify_mode=ssl.CERT_NONE, server_name=authority)
        async with connect(env.http_addr, env.https_port, configuration=config,
                           create_protocol=_SlowUploader) as client:
            sid = client._quic.get_next_available_stream_id()
            client.h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"),
                                         (b":authority", authority.encode()), (b":path", b"/"),
                                         (b"content-length", str(UPLOAD).encode())])
            client.h3.send_data(sid, b"x" * UPLOAD, end_stream=True)
            client.transmit()
            await asyncio.wait_for(client.done, 60)
            return client._quic._remote_max_data - client._quic._remote_max_data_used

    return asyncio.run(run())


class TestFlowWindow:
    """H3MaxWindow caps flow-control window autotuning."""

    def test_001_window_grows_past_the_initial_size(self, env):
        H3Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0
        credit = _upload_credit(env)
        assert credit > INITIAL_WINDOW, f"window stayed at {credit} bytes; autotuning did not run"

    def test_002_cap_holds_the_window(self, env):
        H3Conf(env).add_vhost_test1(extra_lines=[f"H3MaxWindow {INITIAL_WINDOW}"]).install()
        assert env.apache_restart() == 0
        credit = _upload_credit(env)
        assert credit <= INITIAL_WINDOW, f"window grew to {credit} bytes past H3MaxWindow"

    def test_003_rejects_a_window_below_the_initial_size(self, env):
        H3Conf(env).add_vhost_test1(extra_lines=["H3MaxWindow 1000"]).install()
        assert env.apache_restart() != 0
        H3Conf(env).add_vhost_test1().install()
        assert env.apache_restart() == 0
