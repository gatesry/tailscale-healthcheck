import importlib.util
import os
import types


def _load_healthcheck_with_env(env: dict) -> types.ModuleType:
    # Apply env and load a fresh module instance
    here = os.path.dirname(__file__)
    root = os.path.abspath(os.path.join(here, os.pardir))
    module_path = os.path.join(root, "healthcheck.py")
    spec = importlib.util.spec_from_file_location("healthcheck", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    # Isolate env per module load
    old = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(env)
        spec.loader.exec_module(module)  # type: ignore
        return module
    finally:
        os.environ.clear()
        os.environ.update(old)


def test_nodes_url_uses_custom_base_and_user(monkeypatch):
    base = "https://headscale.example.com"
    user = "myspace"
    module = _load_healthcheck_with_env({
        "HEADSCALE_API_BASE_URL": base,
        "HEADSCALE_USER": user,
        "HEADSCALE_API_KEY": "abc",
        "CACHE_ENABLED": "NO",
    })

    calls = {"url": None}

    class DummyResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"nodes": []}

    def fake_get(url, headers=None, timeout=None):
        calls["url"] = url
        return DummyResponse()

    monkeypatch.setattr(module.requests, "get", fake_get)

    # Trigger the call
    devices = module.fetch_devices()
    assert devices == []
    assert calls["url"] == f"{base}/api/v1/node?user={user}"
