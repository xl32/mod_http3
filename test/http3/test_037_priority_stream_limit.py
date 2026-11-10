import asyncio
import ssl

import pytest

from aioquic.asyncio.client import connect
from aioquic.buffer import encode_uint_var
from aioquic.h3.connection import H3_ALPN
from aioquic.quic import events as quic_events
from aioquic.quic.configuration import QuicConfiguration

from .env import H3Conf
from .test_020_malformed import _RawRequestClient

# RFC 9218 section 7.2: PRIORITY_UPDATE for a request stream
FRAME_TYPE_PRIORITY_UPDATE = 0xF0700


class _PriorityClient(_RawRequestClient):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.terminated = None

    def quic_event_received(self, event):
        if isinstance(event, quic_events.ConnectionTerminated):
            self.terminated = event
            self._response_done.set()
        super().quic_event_received(event)

    async def get_with_priority(self, authority, path):
        sid = self._quic.get_next_available_stream_id()
        payload = encode_uint_var(sid) + b"u=2"
        self._quic.send_stream_data(self._http._local_control_stream_id,
                                    encode_uint_var(FRAME_TYPE_PRIORITY_UPDATE)
                                    + encode_uint_var(len(payload)) + payload)
        self._response_done.clear()
        self.status = None
        return await self.get(authority, path)


class TestPriorityStreamLimit:
    """nghttp3 accepts PRIORITY_UPDATE for every stream that MAX_STREAMS allows."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        H3Conf(env).add("H3MaxConcurrentStreams 2").add_vhost_test1().install()
        assert env.apache_restart() == 0

    # Before, nghttp3 kept the first limit (2), so a PRIORITY_UPDATE for the
    # third stream closed the connection with H3_ID_ERROR.
    def test_001_priority_update_past_initial_limit(self, env):
        authority = f"test1.{env.http_tld}"

        async def run():
            config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                       verify_mode=ssl.CERT_NONE, server_name=authority)
            async with connect(env.http_addr, env.https_port, configuration=config,
                               create_protocol=_PriorityClient) as client:
                statuses = []
                for _ in range(6):
                    statuses.append(await client.get_with_priority(authority, "/alive.json"))
                    if client.terminated:
                        break
                return statuses, client.terminated

        statuses, terminated = asyncio.run(run())
        assert terminated is None, terminated
        assert statuses == ["200"] * 6

    # The event loop skips idle sessions; a new packet must wake one again.
    def test_002_request_after_idle(self, env):
        authority = f"test1.{env.http_tld}"

        async def run():
            config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                       verify_mode=ssl.CERT_NONE, server_name=authority)
            async with connect(env.http_addr, env.https_port, configuration=config,
                               create_protocol=_PriorityClient) as client:
                statuses = [await client.get(authority, "/alive.json")]
                for delay in (1.5, 0.2):
                    await asyncio.sleep(delay)
                    client._response_done.clear()
                    client.status = None
                    statuses.append(await client.get(authority, "/alive.json"))
                return statuses

        assert asyncio.run(run()) == ["200"] * 3
