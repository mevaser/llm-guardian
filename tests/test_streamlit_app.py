import importlib

import pytest


def test_streamlit_app_module_imports_when_streamlit_is_available() -> None:
    pytest.importorskip("streamlit")

    module = importlib.import_module("llm_guardian.app.streamlit_app")

    assert hasattr(module, "main")
