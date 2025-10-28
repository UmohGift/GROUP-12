# Password Vault (Local) — GUI
A simple local password manager with a Tkinter GUI...
Password Vault GUI 

A simple and secure Password Vault built with Python (Tkinter) that allows users to:

Store, encrypt, and decrypt passwords safely
Generate strong random passwords
Copy passwords easily to clipboard
Protect all saved data with a master password
Run tests to verify encryption and vault functionality

📂 Project Structure
password_vault_gui_project/
│
├── main.py               # Main application (Tkinter GUI)
├── vault_utils.py        # Handles encryption/decryption and storage logic
├── test_vault.py         # Unit tests for core functionality
├── requirements.txt      # List of dependencies
├── README.md             # Project documentation (this file)
└── /vault_data/          # (Optional) Folder for encrypted storage

⚙️ Features

✅ Secure Master Password – all stored data is protected with AES encryption.
✅ Add & Retrieve Passwords – easily manage account credentials.
✅ Password Strength Indicator – checks password security level.
✅ Copy to Clipboard – one-click password copy using pyperclip.
✅ Automatic Key Derivation – uses PBKDF2 for key safety.
✅ User-Friendly Interface – built using Python’s tkinter.
✅ Unit Tested – includes pytest tests for reliability.

🧰 Installation & Setup
1️⃣ Clone or Download the Project

If you have Git installed:

git clone https://github.com/yourusername/password_vault_gui_project.git


Or just download and extract the ZIP into your preferred directory.

2️⃣ Create a Virtual Environment

Open a terminal or CMD in the project folder and run:

python -m venv venv

Activate it:

venv\Scripts\activate

Install Dependencies

Install all the required libraries:

pip install -r requirements.txt
If requirements.txt is missing, manually install:
pip install cryptography pyperclip tk pytest

 Running the Application
Once dependencies are installed and your virtual environment is active:
python main.py


A window should appear — you can now set a master password, add new accounts, and save your credentials securely.

Running Tests

To verify that everything works correctly:
pytest


You should see something like:

5 tests collected, 5 passed

How It Works (Under the Hood)

Key Derivation:
Your master password is transformed into a secure encryption key using PBKDF2 (with salt).

Encryption:
Passwords are encrypted using AES (Fernet) and stored locally.

Decryption:
When the master password is re-entered, the same key decrypts your stored data.

Clipboard Handling:
The app uses pyperclip to copy passwords without displaying them directly.

Security Notes
Your vault data is encrypted — but keep your master password safe!
If you forget your master password, your data cannot be recovered.
Do not share your vault storage file with others.

 Technologies Used
Python 3.12
Tkinter (GUI)
Cryptography (Fernet AES)
Pyperclip (Clipboard Support)
Pytest (Testing Framework)

Future Improvements
Add search & edit functionality
Enable dark/light theme toggle
Export/import encrypted vault file
Auto-lock after inactivity

