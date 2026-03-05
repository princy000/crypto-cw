import pytest
from ciphermail import AppState
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def test_appstate_creation():
    state = AppState()

    assert state.private_key is None
    assert state.public_key is None
    assert state.key_store == []
    assert state.audit_log == []


def test_key_generation():
    priv, pub = generate_keys()

    assert priv is not None
    assert pub is not None


def test_audit_log():
    state = AppState()

    state.log("test_action", "testing log")

    assert len(state.audit_log) == 1
    assert "hash" in state.audit_log[0]


def test_multiple_logs_chain():
    state = AppState()

    state.log("first", "entry")
    state.log("second", "entry")

    assert len(state.audit_log) == 2
