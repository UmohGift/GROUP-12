import pytest
import json
from vault import PasswordVaultApp  # Make sure PasswordVaultApp is in main.py
import tkinter as tk


class DummyRoot:
    """A simple mock of the Tkinter root window to avoid GUI during testing."""
    def __init__(self):
        self.children = []

    def winfo_children(self):
        """Return a fake list of widgets."""
        return self.children

    def destroy(self):
        """Pretend to destroy the window (does nothing)."""
        pass

    def title(self, text=None):
        """Fake method for setting window title."""
        pass

    def geometry(self, size=None):
        """Fake method for setting window size."""
        pass

    def resizable(self, x=None, y=None):
        """Fake method for window resizing."""
        pass

    def pack(self, *args, **kwargs):
        """Placeholder for any Tkinter packing call."""
        pass

    def grid(self, *args, **kwargs):
        """Placeholder for any grid layout call."""
        pass



@pytest.fixture
def setup_app(tmp_path):
    """Creates a vault app with a hidden Tkinter window (for Tkinter variables)."""
    root = tk.Tk()
    root.withdraw()  # hides the window so it won't show during testing
    app = PasswordVaultApp(root)
    app.storage_file = tmp_path / "test_storage.json"
    return app




def test_key_derivation_same_password(setup_app):
    """Keys derived from the same password should be identical."""
    key1 = setup_app.derive_key("mypassword")
    key2 = setup_app.derive_key("mypassword")
    assert key1 == key2


def test_key_derivation_different_password(setup_app):
    """Keys from different passwords should not match."""
    key1 = setup_app.derive_key("mypassword1")
    key2 = setup_app.derive_key("mypassword2")
    assert key1 != key2


def test_encrypt_decrypt_cycle(setup_app):
    """Data encrypted and then decrypted should return the original."""
    setup_app.key = setup_app.derive_key("testkey")
    sample_data = {"site": {"username": "gift", "password": "123"}}
    setup_app.save_data(sample_data)
    loaded_data = setup_app.load_data()
    assert loaded_data == sample_data


def test_invalid_master_password(setup_app):
    """Decrypting with a wrong password should raise an error."""
    setup_app.key = setup_app.derive_key("correct")
    setup_app.save_data({"test": {"username": "x", "password": "y"}})
    setup_app.key = setup_app.derive_key("wrong")
    with pytest.raises(Exception):
        setup_app.load_data()


def test_password_strength_levels(setup_app):
    """Check that password strength detection works correctly."""
    assert setup_app.check_strength("abc") == "Weak"
    assert setup_app.check_strength("Abcdef12") in ["Medium", "Strong"]
    assert setup_app.check_strength("Abcd!23xyz") == "Strong"
