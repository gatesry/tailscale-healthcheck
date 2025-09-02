import importlib.util
import os
import types
from http.client import RemoteDisconnected


def _load_healthcheck_with_env(env: dict) -> types.ModuleType:
    # Apply env vars and load a fresh module instance
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = str(v)
    here = os.path.dirname(__file__)
    root = os.path.abspath(os.path.join(here, os.pardir))
    module_path = os.path.join(root, "healthcheck.py")
    spec = importlib.util.spec_from_file_location("healthcheck", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_authenticated_request_retries_bounded(monkeypatch):
    module = _load_healthcheck_with_env({
        "MAX_RETRIES": "3",
        "BACKOFF_BASE_SECONDS": "0",
        "BACKOFF_JITTER_SECONDS": "0",
    })

    calls = {"count": 0}

    def always_disconnect(*_a, **_kw):
        calls["count"] += 1
        raise RemoteDisconnected("simulated disconnect")

    # Avoid sleeping during test
    monkeypatch.setattr(module.requests, "get", always_disconnect)
    monkeypatch.setattr(module.time, "sleep", lambda *_a, **_kw: None)

    try:
        module.make_authenticated_request("https://example.invalid", {"Authorization": "Bearer x"})
        assert False, "expected RuntimeError for max retries exceeded"
    except RuntimeError as e:
        assert "Max retries exceeded" in str(e)

    # Should have attempted exactly MAX_RETRIES times
    assert calls["count"] == 3


def test_exponential_backoff_called_between_attempts(monkeypatch):
    module = _load_healthcheck_with_env({
        "MAX_RETRIES": "3",
        "BACKOFF_BASE_SECONDS": "1",
        "BACKOFF_MAX_SECONDS": "10",
        "BACKOFF_JITTER_SECONDS": "0",  # deterministic
    })

    from http.client import RemoteDisconnected as RD
    calls = {"count": 0, "sleeps": []}

    def always_disconnect(*_a, **_kw):
        calls["count"] += 1
        raise RD("oops")

    def record_sleep(secs):
        calls["sleeps"].append(secs)

    monkeypatch.setattr(module.requests, "get", always_disconnect)
    monkeypatch.setattr(module.time, "sleep", record_sleep)

    try:
        module.make_authenticated_request("https://example.invalid", {"Authorization": "Bearer x"})
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass

    # With 3 total attempts, there are 2 sleeps: 1s, then 2s
    assert calls["count"] == 3
    assert len(calls["sleeps"]) == 2
    assert abs(calls["sleeps"][0] - 1.0) < 1e-6
    assert abs(calls["sleeps"][1] - 2.0) < 1e-6


def test_unauthorized_401_propagates(monkeypatch):
    module = _load_healthcheck_with_env({
        "MAX_RETRIES": "1",
    })

    class DummyResponse:
        status_code = 401

        def raise_for_status(self):
            raise Exception("HTTP 401")

    def fake_get(url, headers=None, timeout=None):
        return DummyResponse()

    monkeypatch.setattr(module.requests, "get", fake_get)

    try:
        module.make_authenticated_request("https://example.invalid", {"Authorization": "Bearer x"})
        assert False, "expected exception for 401"
    except Exception as e:
        assert "401" in str(e)
