import argparse
import getpass
import string
import secrets
import pyperclip
import os
import hashlib
import time
import json
import base64
from cryptography.fernet import Fernet, InvalidToken
import csv
import subprocess
import difflib

try:
    import readline
except ImportError:
    readline = None

# Custom Exceptions
class PasmanError(Exception):
    pass

class VaultDecryptionError(PasmanError):
    pass

class SessionExpiredError(PasmanError):
    pass

class VaultCorruptedError(PasmanError):
    pass

# ---- CONSTANTS & CONFIG ----
PASMAN_VERSION = "1.0.0"
GEN_PASS_LENGTH = 16
MAX_HASH_ITERATIONS = 100_000
TOKEN_DURATION_SECONDS = 180  # 3 minutes
SALT_SIZE = 16
HASH_SIZE = 32
AUTH_SIZE = SALT_SIZE + HASH_SIZE
PASSWORD_TRIES = 3

# Allow override via environment variable
VAULT_DIR = os.environ.get("PASMAN_DIR", os.path.expanduser("~"))
VAULT_FILE = os.path.join(VAULT_DIR, ".pasman_vault.json")
TOKEN_FILE = os.path.join(VAULT_DIR, ".pasman_token.txt")
AUTH_FILE = os.path.join(VAULT_DIR, ".pasman_auth.bin")

# ---- UTILITIES ----
def atomic_write(filepath: str, data, is_binary=False):
    tmp_path = filepath + ".tmp"
    mode = "wb" if is_binary else "w"
    
    if os.name == "nt" and os.path.exists(filepath):
        subprocess.run(['attrib', '-h', filepath], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
    with open(tmp_path, mode) as f:
        f.write(data)
    os.replace(tmp_path, filepath)
    
    if os.name == "nt":
        subprocess.run(['attrib', '+h', filepath], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def generate_password() -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(GEN_PASS_LENGTH))
    return password

def copy_to_clipboard(text: str, success_msg: str = "Copied to clipboard!"):
    try:
        pyperclip.copy(text)
        print(success_msg)
    except pyperclip.PyperclipException:
        print("Clipboard copy failed. (No clipboard utility found).")
        ans = input("Would you like to view the password in the terminal? (y/n): ").strip().lower()
        if ans == 'y':
            print(f"Password: {text}")

def setup_readline_completer(vocabulary):
    if readline:
        def completer(text, state):
            results = [x for x in vocabulary if x.startswith(text)] + [None]
            return results[state]
        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

def clear_readline_completer():
    if readline:
        readline.set_completer(None)

# ---- MANAGERS ----
class CryptoManager:
    @staticmethod
    def derive_fernet_key(password: str, salt: bytes) -> bytes:
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, MAX_HASH_ITERATIONS)
        return base64.urlsafe_b64encode(key)

    @staticmethod
    def hash_master_password(password: str, salt: bytes = None) -> bytes:
        if salt is None:
            salt = secrets.token_bytes(SALT_SIZE)
        hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, MAX_HASH_ITERATIONS)
        return salt + hashed

    @staticmethod
    def verify_master_password(password: str, auth_data: bytes) -> bool:
        salt = auth_data[:SALT_SIZE]
        stored_hash = auth_data[SALT_SIZE:]
        input_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, MAX_HASH_ITERATIONS)
        return input_hash == stored_hash

class SessionManager:
    def clear_token(self):
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)

    def create_token(self, fernet_key: bytes):
        self.clear_token()
        content = f"{int(time.time())}\n{fernet_key.decode()}\n"
        atomic_write(TOKEN_FILE, content, is_binary=False)

    def is_valid(self) -> bool:
        if not os.path.exists(TOKEN_FILE):
            return False
        try:
            with open(TOKEN_FILE, "r") as f:
                timestamp = int(f.readline().strip())
            return int(time.time()) - timestamp <= TOKEN_DURATION_SECONDS
        except (ValueError, OSError):
            return False

    def load_fernet_key(self) -> bytes:
        if not os.path.exists(TOKEN_FILE):
            return None
        with open(TOKEN_FILE, "r") as f:
            lines = f.readlines()
            if len(lines) < 2:
                return None
            return lines[1].strip().encode()

class VaultManager:
    def __init__(self):
        self.crypto = CryptoManager()
        self.session = SessionManager()

    def auth_exists(self) -> bool:
        return os.path.exists(AUTH_FILE)

    def load_master_password(self) -> bytes:
        with open(AUTH_FILE, "rb") as f:
            return f.read(AUTH_SIZE)

    def save_master_password(self, hashed_data: bytes):
        atomic_write(AUTH_FILE, hashed_data, is_binary=True)

    def load_encrypted_vault(self, fernet_key: bytes) -> dict:
        if not os.path.exists(VAULT_FILE):
            return {}
        with open(VAULT_FILE, "rb") as f:
            encrypted = f.read()
        if not encrypted:
            return {}
        fernet = Fernet(fernet_key)
        try:
            decrypted = fernet.decrypt(encrypted)
        except InvalidToken:
            raise VaultDecryptionError("Failed to decrypt vault: Invalid token.")
        if not decrypted.strip():
            return {}
        try:
            return json.loads(decrypted.decode())
        except json.JSONDecodeError:
            raise VaultCorruptedError("Vault is corrupted or not in valid JSON format.")

    def save_encrypted_vault(self, vault: dict, fernet_key: bytes) -> bool:
        if not isinstance(vault, dict):
            print("Error: Cannot save vault. Data is not a dictionary.")
            return False
        try:
            fernet = Fernet(fernet_key)
            encrypted = fernet.encrypt(json.dumps(vault).encode())
            atomic_write(VAULT_FILE, encrypted, is_binary=True)
            return True
        except PermissionError:
            print(f"Permission denied: Cannot write to {VAULT_FILE}.")
        except Exception as e:
            print(f"Failed to save vault: {e}")
        return False

    def authenticate(self) -> bool:
        if not self.auth_exists():
            return False
        auth_data = self.load_master_password()
        salt = auth_data[:SALT_SIZE]
        for attempt in range(PASSWORD_TRIES):
            pw = getpass.getpass("Enter master password: ")
            if self.crypto.verify_master_password(pw, auth_data):
                fernet_key = self.crypto.derive_fernet_key(pw, salt)
                self.session.create_token(fernet_key)
                return True
            else:
                print("Incorrect password.")
        print("Too many failed attempts.")
        return False

    def get_authenticated_vault(self):
        if not self.auth_exists():
            print("Set a Master password first using 'init'.")
            return None, None
        
        if not self.session.is_valid():
            if not self.authenticate() or not self.session.is_valid():
                raise SessionExpiredError("Invalid Session.")
        
        fernet_key = self.session.load_fernet_key()
        if not fernet_key:
            self.session.clear_token()
            raise SessionExpiredError("Session invalid or corrupted. Re-authentication required.")
        
        vault = self.load_encrypted_vault(fernet_key)
        return vault, fernet_key

# ---- CLI LOGIC ----
class PasmanCLI:
    def __init__(self):
        self.vault_manager = VaultManager()

    def run(self):
        parser = argparse.ArgumentParser(description="Pasman - A Lightweight CLI Password Manager")
        parser.add_argument("--version", "-v", action="version", version=f"Pasman {PASMAN_VERSION}")
        
        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Commands without strict arguments
        subparsers.add_parser("init", help="Initialize or unlock with master password")
        subparsers.add_parser("reset", help="Reset the master password")
        subparsers.add_parser("quit", help="Clear current login session")
        subparsers.add_parser("create", help="Generate a strong password")
        
        list_parser = subparsers.add_parser("list", help="List stored entries")
        list_parser.add_argument("--expanded", "-e", action="store_true", help="List all stored entries with details")

        # Commands with arguments
        add_parser = subparsers.add_parser("add", help="Add a new password")
        add_parser.add_argument("service", nargs="?", help="Service name")
        add_parser.add_argument("username", nargs="?", help="Username/email")

        fetch_parser = subparsers.add_parser("fetch", help="Fetch a password")
        fetch_parser.add_argument("service", nargs="?", help="Service name")
        fetch_parser.add_argument("username", nargs="?", help="Username/email")
        fetch_parser.add_argument("--show", action="store_true", help="Show password in terminal after fetching")

        rm_parser = subparsers.add_parser("remove", help="Remove a stored password entry")
        rm_parser.add_argument("service", nargs="?", help="Service name")
        rm_parser.add_argument("username", nargs="?", help="Username/email")

        edit_parser = subparsers.add_parser("edit", help="Edit an existing password entry")
        edit_parser.add_argument("service", nargs="?", help="Service name")
        edit_parser.add_argument("username", nargs="?", help="Username/email")

        export_parser = subparsers.add_parser("export", help="Export your encrypted vault to a file")
        export_parser.add_argument("path", help="Export destination path")

        import_parser = subparsers.add_parser("import", help="Import vault from another file")
        import_parser.add_argument("path", help="Import source path")

        import_txt_parser = subparsers.add_parser("import-txt", help="Import passwords from .txt file (CSV format)")
        import_txt_parser.add_argument("path", help="Filepath to import from")

        args = parser.parse_args()

        if not args.command:
            parser.print_help()
            return

        try:
            self.execute_command(args)
        except PasmanError as e:
            print(f"Error: {e}")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")

    def execute_command(self, args):
        cmd = args.command
        
        if cmd == "quit":
            self.vault_manager.session.clear_token()
            print("Logged out of session.")
            return

        if cmd == "create":
            password = generate_password()
            print(f"Generated password: {password}")
            copy_to_clipboard(password)
            return

        if cmd == "init":
            self.handle_init()
            return

        if cmd == "reset":
            self.handle_reset()
            return

        if cmd in ["add", "fetch", "remove", "edit", "list", "export", "import", "import-txt"]:
            if not self.vault_manager.auth_exists():
                print("Set a Master password first using 'init'.")
                return

        if cmd == "list":
            self.handle_list(args.expanded)
        elif cmd == "add":
            self.handle_add(args.service, args.username)
        elif cmd == "fetch":
            self.handle_fetch(args.service, args.username, getattr(args, 'show', False))
        elif cmd == "remove":
            self.handle_remove(args.service, args.username)
        elif cmd == "edit":
            self.handle_edit(args.service, args.username)
        elif cmd == "export":
            self.handle_export(args.path)
        elif cmd == "import":
            self.handle_import(args.path)
        elif cmd == "import-txt":
            self.handle_import_txt(args.path)

    # --- Command Handlers ---
    def handle_init(self):
        if not self.vault_manager.auth_exists():
            print("No Master password found. Initialize user:")
            while True:
                pw1 = getpass.getpass("Set master password: ")
                pw2 = getpass.getpass("Confirm password: ")
                if pw1 == pw2:
                    hashed = self.vault_manager.crypto.hash_master_password(pw1)
                    self.vault_manager.save_master_password(hashed)
                    fernet_key = self.vault_manager.crypto.derive_fernet_key(pw1, hashed[:SALT_SIZE])
                    self.vault_manager.session.create_token(fernet_key)
                    print("Master password set.")
                    print(f"Session active for next {TOKEN_DURATION_SECONDS // 60} minutes.")
                    return
                else:
                    print("Passwords do not match. Try again.")
        else:
            if self.vault_manager.session.is_valid():
                print("Session already active.")
                return
            if not self.vault_manager.authenticate():
                return
            print(f"Login successful! Session active for next {TOKEN_DURATION_SECONDS // 60} minutes.")

    def handle_reset(self):
        if not self.vault_manager.authenticate():
            return
        old_fernet_key = self.vault_manager.session.load_fernet_key()
        if not old_fernet_key:
            raise SessionExpiredError("Session invalid.")
        vault = self.vault_manager.load_encrypted_vault(old_fernet_key)
        
        print("Reset your master password:")
        while True:
            new_pw1 = getpass.getpass("Set new master password: ")
            new_pw2 = getpass.getpass("Confirm password: ")
            if new_pw1 == new_pw2:
                new_salt = secrets.token_bytes(SALT_SIZE)
                new_hash = self.vault_manager.crypto.hash_master_password(new_pw1, new_salt)
                self.vault_manager.save_master_password(new_hash)
                new_fernet_key = self.vault_manager.crypto.derive_fernet_key(new_pw1, new_salt)
                if self.vault_manager.save_encrypted_vault(vault, new_fernet_key):
                    print("Master password changed successfully.")
                else:
                    print("Failed to save vault with new password.")
                self.vault_manager.session.clear_token()
                return
            else:
                print("Passwords do not match. Try again.")

    def get_service_interactive(self, vault: dict, provided_service: str) -> str:
        services = list(vault.keys())
        setup_readline_completer(services)
        
        service = provided_service
        if not service:
            if not services:
                return None
            print("Available services:")
            for svc in services:
                print(" -", svc)
            service = input("Enter service: ").strip().lower()
            
        clear_readline_completer()

        if service not in vault:
            matches = difflib.get_close_matches(service, services, n=1, cutoff=0.6)
            if matches:
                ans = input(f"Did you mean '{matches[0]}'? (y/n): ").strip().lower()
                if ans == 'y':
                    return matches[0]
            print(f"Service '{service}' not found.")
            return None
            
        return service

    def get_username_interactive(self, vault: dict, service: str, provided_username: str) -> str:
        users = list(vault[service].keys())
        username = provided_username
        
        if not username:
            if len(users) == 1:
                return users[0]
                
            print(f"Available accounts for '{service}':")
            for i, user in enumerate(users, 1):
                print(f" {i}. {user}")
                
            setup_readline_completer(users)
            sel = input("Select number or type username: ").strip()
            clear_readline_completer()
            
            if sel.isdigit() and 1 <= int(sel) <= len(users):
                username = users[int(sel) - 1]
            else:
                username = sel

        if username not in vault[service]:
            print(f"Account '{username}' not found for service '{service}'.")
            return None
            
        return username

    def handle_add(self, service, username):
        vault, fernet_key = self.vault_manager.get_authenticated_vault()
        
        if not service:
            setup_readline_completer(list(vault.keys()))
            service = input("Enter service name (e.g., gmail): ").strip().lower()
            clear_readline_completer()
        if not username:
            username = input("Enter username/email: ").strip()
            
        password = getpass.getpass("Enter password (leave blank to generate one): ").strip()
        if not password:
            password = generate_password()
            print(f"Generated password: {password}")
            copy_to_clipboard(password)

        if service not in vault:
            vault[service] = {}
        if username in vault[service]:
            print("Entry already exists for this service and username.")
            return

        vault[service][username] = password
        if self.vault_manager.save_encrypted_vault(vault, fernet_key):
            print("Password added successfully.")

    def handle_fetch(self, service, username, show):
        vault, fernet_key = self.vault_manager.get_authenticated_vault()
        if not vault:
            print("Vault is empty.")
            return

        service = self.get_service_interactive(vault, service)
        if not service: return
        
        username = self.get_username_interactive(vault, service, username)
        if not username: return

        password = vault[service][username]
        copy_to_clipboard(password)
        if show:
            print(f"Password for {username} on {service}: {password}")

    def handle_remove(self, service, username):
        vault, fernet_key = self.vault_manager.get_authenticated_vault()
        if not vault:
            print("Vault is empty.")
            return

        service = self.get_service_interactive(vault, service)
        if not service: return
        
        username = self.get_username_interactive(vault, service, username)
        if not username: return

        confirm = input(f"Are you sure you want to delete the password for {username} on {service}? (y/n): ").strip().lower()
        if confirm != 'y':
            print("Operation cancelled.")
            return

        del vault[service][username]
        if not vault[service]:
            del vault[service]

        if self.vault_manager.save_encrypted_vault(vault, fernet_key):
            print("Password entry removed successfully.")

    def handle_edit(self, service, username):
        vault, fernet_key = self.vault_manager.get_authenticated_vault()
        if not vault:
            print("Vault is empty.")
            return

        service = self.get_service_interactive(vault, service)
        if not service: return
        
        username = self.get_username_interactive(vault, service, username)
        if not username: return

        print("\n--- Leave blank to keep current value ---")
        new_service = input(f"New service name (current: {service}): ").strip().lower()
        new_username = input(f"New username/email (current: {username}): ").strip()
        new_password = getpass.getpass("New password (leave blank to generate): ").strip()

        new_service = new_service if new_service else service
        new_username = new_username if new_username else username
        if not new_password:
            new_password = generate_password()
            print(f"Generated password: {new_password}")
            copy_to_clipboard(new_password)

        if new_service != service or new_username != username:
            del vault[service][username]
            if not vault[service]:
                del vault[service]

        if new_service not in vault:
            vault[new_service] = {}

        vault[new_service][new_username] = new_password
        if self.vault_manager.save_encrypted_vault(vault, fernet_key):
            print("Entry updated successfully.")

    def handle_list(self, expanded):
        vault, _ = self.vault_manager.get_authenticated_vault()
        if not vault:
            print("Vault is empty.")
            return

        if expanded:
            print("\nStored Entries:")
            for service, users in vault.items():
                print(f"{service}:")
                for username in users:
                    print(f"   • {username}")
        
        total_services = len(vault)
        total_accounts = sum(len(users) for users in vault.values())
        print("\n--- Vault Summary ---")
        print(f"Total Services  : {total_services}")
        print(f"Total Accounts  : {total_accounts}")

    def handle_export(self, destination_path):
        auth_data = self.vault_manager.load_master_password()
        salt = auth_data[:SALT_SIZE]

        if not os.path.exists(VAULT_FILE):
            print("No vault file to export.")
            return

        try:
            with open(VAULT_FILE, "rb") as f_src:
                vault_data = f_src.read()

            with open(destination_path, "wb") as f_dst:
                f_dst.write(salt + vault_data)
            print(f"Vault exported successfully to {destination_path}")
        except Exception as e:
            print(f"Failed to export vault: {e}")

    def handle_import(self, path):
        if not os.path.exists(path):
            print("Provided import file does not exist.")
            return
            
        _, local_fernet_key = self.vault_manager.get_authenticated_vault()

        try:
            with open(path, "rb") as f:
                raw_import_data = f.read()

            imported_salt = raw_import_data[:SALT_SIZE]
            encrypted_vault_blob = raw_import_data[SALT_SIZE:]

            pw = getpass.getpass("Enter master password for the imported file: ")
            imported_device_key = self.vault_manager.crypto.derive_fernet_key(pw, imported_salt)
            
            import_cipher = Fernet(imported_device_key)
            decrypted_raw = import_cipher.decrypt(encrypted_vault_blob)
            imported_vault = json.loads(decrypted_raw.decode())

        except InvalidToken:
            print("Failed to decrypt imported vault. Incorrect password or corrupted file.")
            return
        except (json.JSONDecodeError, UnicodeDecodeError):
            print("Imported data is corrupted or not valid JSON.")
            return
        except Exception as e:
            print(f"Failed to read or decrypt import file: {e}")
            return

        try:
            current_vault = self.vault_manager.load_encrypted_vault(local_fernet_key)
        except Exception:
            print("Warning: Failed to decrypt existing local vault. Starting with empty.")
            current_vault = {}

        added, skipped = 0, 0
        for service, entries in imported_vault.items():
            if service not in current_vault:
                current_vault[service] = entries
                added += len(entries)
            else:
                for user, pwd in entries.items():
                    if user not in current_vault[service]:
                        current_vault[service][user] = pwd
                        added += 1
                    else:
                        skipped += 1

        if self.vault_manager.save_encrypted_vault(current_vault, local_fernet_key):
            print(f"Import complete. Added: {added}, Skipped: {skipped} duplicates.")

    def handle_import_txt(self, filepath):
        if not os.path.exists(filepath):
            print("Import file not found.")
            return
            
        _, fernet_key = self.vault_manager.get_authenticated_vault()

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                lines = list(reader)
        except UnicodeDecodeError:
            print("Error: Could not decode file. Ensure it's UTF-8 encoded.")
            return
        except csv.Error as e:
            print(f"CSV format error: {e}")
            return
            
        try:
            current_vault = self.vault_manager.load_encrypted_vault(fernet_key)
        except Exception:
            current_vault = {}

        added, skipped = 0, 0
        for parts in lines:
            if len(parts) != 3:
                skipped += 1
                continue
            
            service, username, password = [part.strip() for part in parts]
            service = service.lower()
            
            if not service or not username:
                skipped += 1
                continue

            if service not in current_vault:
                current_vault[service] = {}

            if username in current_vault[service]:
                skipped += 1
                continue

            current_vault[service][username] = password
            added += 1

        if self.vault_manager.save_encrypted_vault(current_vault, fernet_key):
            print(f"Import complete. Added: {added}, Skipped: {skipped}")

if __name__ == "__main__":
    app = PasmanCLI()
    app.run()
