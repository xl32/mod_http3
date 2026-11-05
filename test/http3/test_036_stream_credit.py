import asyncio
import ssl

import pytest

from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from .env import H3Conf
from .test_020_malformed import _RawRequestClient


class TestStreamCredit:
    """The server gives a stream back each time a client stream closes."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        H3Conf(env).add("H3MaxConcurrentStreams 2").add_vhost_test1().install()
        assert env.apache_restart() == 0

    # Without new MAX_STREAMS credit the third request on the connection cannot open a stream.
    def test_001_more_requests_than_streams(self, env):
        authority = f"test1.{env.http_tld}"

        async def run():
            config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                       verify_mode=ssl.CERT_NONE, server_name=authority)
            async with connect(env.http_addr, env.https_port, configuration=config,
                               create_protocol=_RawRequestClient) as client:
                initial = client._quic._remote_max_streams_bidi
                statuses = []
                for _ in range(6):
                    client._response_done.clear()
                    statuses.append(await client.get(authority, "/alive.json"))
                return initial, statuses

        initial, statuses = asyncio.run(run())
        assert initial == 2
        assert statuses == ["200"] * 6
