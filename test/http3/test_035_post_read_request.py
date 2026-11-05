import pytest

from .env import H3Conf


class TestPostReadRequest:
    """HTTP/3 requests run the post_read_request hooks, as HTTP/1.1 and HTTP/2 do."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        H3Conf(env).add_vhost_test1(extra_lines=[
            'SetEnvIf User-Agent "^blocked-agent$" blocked',
            '<Location "/">',
            '  <RequireAll>',
            '    Require all granted',
            '    Require not env blocked',
            '  </RequireAll>',
            '</Location>',
            'SetEnvIf Request_Protocol "^(.+)$" seen_proto=$1',
            'Header always set X-Seen-Protocol "%{seen_proto}e"',
        ]).install()
        assert env.apache_restart() == 0

    def get(self, env, *opts):
        r = env.curl_get(env.mkurl("https", "test1", "/alive.json"),
                         options=["--http3-only", "-k", *opts])
        assert r.exit_code == 0, r.stderr + r.stdout
        return r.response

    # Server-level SetEnvIf runs in post_read_request; Require must see it.
    def test_001_setenvif_access(self, env):
        assert self.get(env, "-A", "blocked-agent")["status"] == 403
        assert self.get(env, "-A", "other-agent")["status"] == 200
        env.httpd_error_log.ignore_recent(lognos=["AH01630"])

    # SetEnvIf sees the protocol that mod_http3 sets in its own hook.
    def test_002_protocol(self, env):
        assert self.get(env)["header"].get("x-seen-protocol") == "HTTP/3.0"
