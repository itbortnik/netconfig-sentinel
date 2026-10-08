"""Actual optional SDK against owned redirect servers, not a Batfish/formal result."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from threading import Thread
from types import SimpleNamespace
from typing import Any

import pytest
from app.verification import batfish_worker


@pytest.mark.parametrize("code", [302, 307, 308])
@pytest.mark.parametrize("method", ["get", "post", "put", "delete"])
def test_real_sdk_does_not_follow_owned_redirect(
    monkeypatch: pytest.MonkeyPatch, code: int, method: str
) -> None:
    sdk = pytest.importorskip("pybatfish.client.session", reason="requires the optional pinned SDK")
    rest = pytest.importorskip("pybatfish.client.restv2helper")
    requests = {"redirect": 0, "collector": 0}
    monkeypatch.setenv("NO_PROXY", "*")
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)

    class Collector(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests["collector"] += 1
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_POST = do_PUT = do_DELETE = do_GET

        def log_message(self, *args: Any) -> None:
            pass

    collector = ThreadingHTTPServer(("127.0.0.1", 0), Collector)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests["redirect"] += 1
            self.send_response(code)
            self.send_header("Location", f"http://127.0.0.1:{collector.server_port}/collector")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_POST = do_PUT = do_DELETE = do_GET

        def log_message(self, *args: Any) -> None:
            pass

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    servers = (collector, redirect)
    threads = [Thread(target=server.serve_forever, daemon=True) for server in servers]

    def owned_session(**kwargs: Any) -> Any:
        assert kwargs["host"] == "127.0.0.1" and kwargs["port"] == 9996
        # Only this laboratory test substitutes an owned ephemeral port. The
        # production factory has no endpoint/port override and never uses it.
        return sdk.Session(
            **{**kwargs, "port": redirect.server_port}, load_questions=False, timeout=2
        )

    monkeypatch.setattr(
        batfish_worker.importlib,
        "import_module",
        lambda name: SimpleNamespace(Session=owned_session),
    )
    try:
        for thread in threads:
            thread.start()
        session = batfish_worker._session()
        with pytest.raises(batfish_worker.BatfishRedirectRefused):
            if method == "get":
                session.get_component_versions()
            elif method == "post":
                rest._post(session, "/owned", obj=None, stream=BytesIO(b"owned-laboratory-only"))
            elif method == "put":
                rest._put(session, "/owned", stream=BytesIO(b"owned-laboratory-only"))
            else:
                rest._delete(session, "/owned")
        assert requests == {"redirect": 1, "collector": 0}
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
        assert all(not thread.is_alive() for thread in threads)
