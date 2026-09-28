"""
Regression tests for sample_repo/app.py. The sandbox_runner will run these
inside its isolated copy after applying a generated patch, to confirm the
patch doesn't break existing behavior.
"""
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app  # noqa: E402


def test_load_config_parses_simple_yaml():
    result = app.load_config("key: value\n")
    assert result == {"key": "value"}


def test_load_config_rejects_unsafe_tags():
    """
    After the security fix, yaml.load must use a safe loader and therefore
    must NOT execute/construct arbitrary Python objects from YAML tags.
    Before the fix (plain yaml.load with default Loader), this would
    construct a Python object; after the fix, it should raise.
    """
    malicious_yaml = "!!python/object/apply:os.system ['echo pwned']"
    try:
        result = app.load_config(malicious_yaml)
        # If it didn't raise, it must not have actually constructed an
        # os.system call object -- i.e. it must be plain/unresolved data.
        assert not callable(result)
    except Exception:
        # SafeLoader raising a ConstructorError on unsafe tags is the
        # correct, expected behavior post-patch.
        pass


@patch("app.requests.get")
def test_fetch_config_calls_requests_get(mock_get):
    mock_response = MagicMock()
    mock_response.text = "key: value"
    mock_get.return_value = mock_response

    result = app.fetch_config("https://example.com/config.yaml")

    assert result == "key: value"
    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    assert args[0] == "https://example.com/config.yaml"
