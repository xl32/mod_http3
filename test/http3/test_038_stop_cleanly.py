import os
import re
import time

import pytest

from .env import H3Conf

# From httpd trunk test_h3_014_04 (apache/httpd#993).
CRASH = re.compile(r".*\bexit signal (?:Segmentation fault|Abort(ed)?|Bus error)\b.*")
# The parent gave up waiting for a child: AH00045, AH00046.
STUCK = re.compile(r".*AH0004[56]: child process.*")
ASAN = re.compile(r".*==\d+==ERROR: (?:Address|Memory|Leak|Thread)Sanitizer:.*")


class TestStopCleanly:
    """Children with HTTP/3 sessions exit cleanly on stop, many times over."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        H3Conf(env).add_vhost_test1().install()

    def _h3_get(self, env, url):
        deadline = time.monotonic() + 10
        while True:
            r = env.curl_get(url, options=["--http3-only", "-k"])
            if r.exit_code == 0 or time.monotonic() >= deadline:
                return r
            time.sleep(0.2)

    def test_001_stop_cleanly(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        path = env.httpd_error_log.path
        start = os.path.getsize(path) if os.path.isfile(path) else 0
        for i in range(20):
            assert env.apache_restart() == 0, f"cycle {i}: start"
            r = self._h3_get(env, url)
            assert r.exit_code == 0, f"cycle {i}: {r.stderr}"
            assert r.response["protocol"] == "HTTP/3"
            assert env.apache_stop() == 0, f"cycle {i}: stop"
        with open(path) as fd:
            fd.seek(start)
            bad = [l for l in fd if CRASH.match(l) or STUCK.match(l) or ASAN.match(l)]
        env.httpd_error_log.ignore_recent(matches=[CRASH.pattern, STUCK.pattern, ASAN.pattern])
        assert not bad, "".join(bad)
