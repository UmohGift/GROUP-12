import pytest
import json
from main import PasswordVaultApp

class DummyRoot:
    """Simple stand-in for Tkinter root (avoids GUI dependency)."""
    def winfo_children(self): return []
    def destroy(self): pass

@pytest.fixture
def setup_app(tmp_path):
    """Creates a vault app with isolated storage file (no GUI needed)."""
    app = PasswordVaultApp(DummyRoot())
    app.storage_file = tmp_path / "test_storage.json"
    return app

def test_key_derivation_same_password(setup_app):
    key1 = setup_app.derive_key("mypassword")
    key2 = setup_app.derive_key("mypassword")
    assert key1 == key2

def test_key_derivation_different_password(setup_app):
    key1 = setup_app.derive_key("mypassword1")
    key2 = setup_app.derive_key("mypassword2")
    assert key1 != key2

def test_encrypt_decrypt_cycle(setup_app):
    setup_app.key = setup_app.derive_key("testkey")
    sample_data = {"site": {"username": "gift", "password": "123"}}
    setup_app.save_data(sample_data)
    loaded_data = setup_app.load_data()
    assert loaded_data == sample_data

def test_invalid_master_password(setup_app):
    setup_app.key = setup_app.derive_key("correct")
    setup_app.save_data({"test": {"username": "x", "password": "y"}})
    setup_app.key = setup_app.derive_key("wrong")
    with pytest.raises(Exception):
        setup_app.load_data()

def test_password_strength_levels(setup_app):
    assert setup_app.check_strength("abc") == "Weak"
    assert setup_app.check_strength("Abcdef12") in ["Medium", "Strong"]
    assert setup_app.check_strength("Abcd!23xyz") == "Strong"
