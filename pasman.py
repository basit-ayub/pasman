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
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import csv
import subprocess

#Files
VAULT_DIR = os.path.expanduser("~")  # C:\Users\YourName
VAULT_FILE = os.path.join(VAULT_DIR, ".pasman_vault.json")
TOKEN_FILE = os.path.join(VAULT_DIR, ".pasman_token.txt")
AUTH_FILE  = os.path.join(VAULT_DIR, ".pasman_auth.bin")


# ----CONSTANTS----
PASMAN_VERSION="1.0.0"
GEN_PASS_LENGTH = 16
MAX_HASH_ITERATIONS = 100_000
TOKEN_DURATION_SECONDS = 180  # 3 minutes
SALT_SIZE=16
HASH_SIZE=32
AUTH_SIZE = SALT_SIZE + HASH_SIZE
PASSWORD_TRIES=3
WIN_HIDDEN_ATTR=2

#----FUNCTIONS----
#Create a password
def generate_password() -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(GEN_PASS_LENGTH))
    return password

#TOKEN FUNCTIONS

#Clear the current Session
def clear_token():
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)

#Create a Valid Token
def create_token(fernet_key: bytes):
    if os.path.exists(TOKEN_FILE):
        clear_token()
    if os.name == "nt":
        subprocess.run(['attrib', '-h', TOKEN_FILE], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(TOKEN_FILE, "w") as f:
        f.write(f"{int(time.time())}\n")
        f.write(f"{fernet_key.decode()}\n")

    if os.name == "nt":
        subprocess.run(['attrib', '-h', TOKEN_FILE], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


#Check Token Validity
def token_is_valid() -> bool:
    if not os.path.exists(TOKEN_FILE):
        return False
    with open(TOKEN_FILE, "r") as f:
        timestamp = int(f.readline().strip())
    return int(time.time()) - timestamp <= TOKEN_DURATION_SECONDS

#Retrieve data from Token
def load_fernet_key_from_token() -> bytes | None:
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE, "r") as f:
        lines = f.readlines()
        if len(lines) < 2:
            return None
        return lines[1].strip().encode()

#Fernet Functions
# Derive a Fernet key from master password hash
def derive_fernet_key(password: str, salt: bytes) -> bytes:
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, MAX_HASH_ITERATIONS)
    return base64.urlsafe_b64encode(key)

#---Vault Functions----
def load_encrypted_vault(fernet_key: bytes) -> dict:
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    if not encrypted:
            return {}
    fernet = Fernet(fernet_key)
    decrypted = fernet.decrypt(encrypted)
    if not decrypted.strip():
        return {}
    return json.loads(decrypted.decode())


def save_encrypted_vault(vault: dict, fernet_key: bytes):
    if not isinstance(vault, dict):
        print("Error: Cannot save vault. Data is not a dictionary.")
        return False

    try:
        fernet = Fernet(fernet_key)
        encrypted = fernet.encrypt(json.dumps(vault).encode())

        if os.name=="nt":
            subprocess.run(['attrib', '-h', VAULT_FILE], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted)

        if os.name=="nt":
            subprocess.run(['attrib', '+h', VAULT_FILE], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return True
    except PermissionError:
        print(f"Permission denied: Cannot write to {VAULT_FILE}. Please check file permissions or run as administrator.")
    except Exception as e:
        print(f"Failed to save vault: {e}")
    return False







#Auth Functions
#Hashes the Master Password
def hash_master_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, MAX_HASH_ITERATIONS)
    return salt + hashed

# Checks the Master Password against stored Hash
def verify_master_password(password, auth_data):
    salt = auth_data[:SALT_SIZE]
    stored_hash = auth_data[SALT_SIZE:]
    input_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, MAX_HASH_ITERATIONS)
    return input_hash == stored_hash

# Write to AUTH FILE in binary
def save_master_password(hashed_data):
    if os.name == "nt":
        subprocess.run(['attrib', '-h', AUTH_FILE], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(AUTH_FILE, "wb") as f:
        f.write(hashed_data)
    if os.name == "nt":
        subprocess.run(['attrib', '-h', AUTH_FILE], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# Get contents of the auth file
def load_master_password():
    with open(AUTH_FILE, "rb") as f:
        return f.read(AUTH_SIZE)

def auth_exists():
    return os.path.exists(AUTH_FILE)

def authenticate() -> bool:
    auth_data = load_master_password()
    salt = auth_data[:SALT_SIZE]
    for attempt in range(PASSWORD_TRIES):
        pw = getpass.getpass("Enter master password: ")
        if verify_master_password(pw, auth_data):
            fernet_key=derive_fernet_key(pw,salt)
            create_token(fernet_key)
            return True
        else:
            print("Incorrect password.")
    print("Too many failed attempts.")
    return False

#Vault Helper
def load_authenticated_vault() -> tuple[dict, bytes] | None:
    if not auth_exists():
        print("Set a Master password first using -init.")
        return None
    if not token_is_valid():
        if not authenticate() or not token_is_valid():
            print("Invalid Session.")
            return None
    fernet_key = load_fernet_key_from_token()
    if not fernet_key:
        print("Session invalid or corrupted. Re-authentication required.")
        clear_token()
        return None
    try:
        vault = load_encrypted_vault(fernet_key)
        if not isinstance(vault, dict):
            raise json.JSONDecodeError("Vault is not a dictionary", "", 0)
    except InvalidToken:
        print("Failed to decrypt vault: Invalid or expired session.")
        return None
    except FileNotFoundError:
        print("Vault file not found.")
        return None
    except json.JSONDecodeError:
        print("Vault is empty or corrupted.")
        return None
    return vault, fernet_key
#Export the vault
def export_vault(destination_path: str):
    if not os.path.exists(VAULT_FILE):
        print("No vault file to export.")
        return
    try:
        with open(VAULT_FILE, "rb") as f_src:
            data = f_src.read()
        with open(destination_path, "wb") as f_dst:
            f_dst.write(data)
        print(f"Vault exported to {destination_path}")
    except Exception as e:
        print(f"Failed to export vault: {e}")

def import_vault(path: str, fernet_key: bytes):
    if not os.path.exists(path):
        print("Provided import file does not exist.")
        return

    try:
        with open(path, "rb") as f:
            imported_data = f.read()
    except (OSError, IOError) as e:
        print(f"Failed to read import file: {e}")
        return

    try:
        imported_fernet = Fernet(fernet_key)
        imported_vault = json.loads(imported_fernet.decrypt(imported_data).decode())
    except InvalidToken:
        print("Failed to decrypt imported vault. Check master password.")
        return
    except json.JSONDecodeError:
        print("Decrypted data is not valid JSON.")
        return
    except UnicodeDecodeError:
        print("Decrypted data is not valid UTF-8.")
        return

    # Load current vault or create empty one
    if os.path.exists(VAULT_FILE):
        try:
            current_vault = load_encrypted_vault(fernet_key)
        except InvalidToken:
            print("Warning: Failed to decrypt existing vault with current key.")
            current_vault = {}
        except json.JSONDecodeError:
            print("Warning: Existing vault is not valid JSON. Starting with an empty vault.")
            current_vault = {}
        except Exception as e:
            print(f"Warning: Unexpected error loading current vault: {e}")
            current_vault = {}
    else:
        current_vault = {}

    added = 0
    skipped = 0

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
                    print(f"Skipped duplicate entry: {service} → {user}")
                    skipped += 1

    if save_encrypted_vault(current_vault, fernet_key):
        print("Password added successfully.")
    else:
        print("Failed to save password.")

    print(f"Imported vault successfully. Added: {added}, Skipped: {skipped}")

def import_txt_file(filepath: str, fernet_key: bytes):
    if not os.path.exists(filepath):
        print("Import file not found.")
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            lines = list(reader)
    except FileNotFoundError:
        print("Error: File not found.")
        return
    except UnicodeDecodeError:
        print("Error: Could not decode file. Ensure it's UTF-8 encoded.")
        return
    except csv.Error as e:
        print(f"CSV format error: {e}")
        return
    except Exception as e:
        print(f"Unexpected error while reading file: {e}")
        return

    try:
        current_vault = load_encrypted_vault(fernet_key)
    except InvalidToken:
        print("Error: Could not decrypt current vault. Possibly wrong master password.")
        return
    except json.JSONDecodeError:
        print("Error: Current vault is corrupted or not in valid JSON format.")
        return
    except FileNotFoundError:
        current_vault = {}
    except Exception as e:
        print(f"Unexpected error while loading vault: {e}")
        return

    added = 0
    skipped = 0
    for parts in lines:
        if len(parts) != 3:
            skipped += 1
            continue

        try:
            service, username, password = [part.strip() for part in parts]
            service = service.lower()

            if service not in current_vault:
                current_vault[service] = {}

            if username in current_vault[service]:
                skipped += 1
                continue

            current_vault[service][username] = password
            added += 1
        except Exception as e:
            print(f"Error importing line {parts}: {e}")
            skipped += 1
    try:
        save_encrypted_vault(current_vault, fernet_key)
        print(f"Import complete. Added: {added}, Skipped: {skipped}")
    except Exception as e:
        print(f"Error saving vault: {e}")






# --- Main Program ---
def main():
    parser = argparse.ArgumentParser(
        description="Pasman - A Lightweight CLI Password Manager"
    )
    # --- Core Commands ---
    parser.add_argument("--init", "-i", action="store_true", help="Initialize or unlock with master password")
    parser.add_argument("--reset", "-r", action="store_true", help="Reset the master password")
    parser.add_argument("--quit", "-q", action="store_true", help="Clear current login session")

    # --- Password Operations ---
    parser.add_argument("-a", "--add", nargs="?", const=True, metavar="ENTRY",
                        help="Add a new password (format: service,username,password)")
    parser.add_argument("-f", "--fetch", nargs="?", const=True, metavar="QUERY",
                        help="Fetch a password (format: service,username)")
    parser.add_argument("--remove", "-rm", action="store_true", help="Remove a stored password entry")
    parser.add_argument("--edit", "-e", action="store_true", help="Edit an existing password entry")
    parser.add_argument("--show", action="store_true", help="Show password after fetching")

    # --- Listing Options ---
    parser.add_argument("-l", "--list", dest="list_summary", action="store_true", help="Show summary of stored entries")
    parser.add_argument("-L", "--list-show", dest="list_expanded", action="store_true",
                        help="List all stored entries with details")

    # --- Utilities ---
    parser.add_argument("--create", "-c", action="store_true", help="Generate a strong password")
    parser.add_argument("--version", "-v", action="store_true", help="Show the version of Pasman")

    # --- Vault Import/Export ---
    parser.add_argument("--export", "-ex", metavar="EXPORT_PATH", help="Export your encrypted vault to a file")
    parser.add_argument("--import", "-im", dest="import_path", metavar="IMPORT_PATH",
                        help="Import vault from another file")
    parser.add_argument("--import-txt", "-it", dest="import_txt", metavar="FILEPATH",
                        help="Import passwords from .txt file (format: service,username,password)")

    args = parser.parse_args()

    # Handle session logout
    if args.quit:
        clear_token()
        print("Logged out of session.")
        return

    # Generate a strong password
    if args.create:
        password=generate_password()
        print(f"Generated password: {password}")
        pyperclip.copy(password)
        print("Copied to clipboard!")
        return

    # Handle master password logic
    if args.init:
        if not auth_exists():
            # First time setup
            print("No Master password found. Initialize user:")
            while True:
                pw1 = getpass.getpass("Set master password: ")
                pw2 = getpass.getpass("Confirm password: ")
                if pw1 == pw2:
                    hashed = hash_master_password(pw1)
                    save_master_password(hashed)

                    # Create session immediately
                    auth_data = load_master_password()
                    salt = auth_data[:SALT_SIZE]
                    fernet_key = derive_fernet_key(pw1, salt)
                    create_token(fernet_key)

                    print("Master password set.")
                    print(f"Session active for next {TOKEN_DURATION_SECONDS / 60} minutes.")
                    return
                else:
                    print("Passwords do not match. Try again.")
        else:
            if token_is_valid():
                print("Session already active.")
                return
            if not authenticate():
                return
            print(f"Login successful! Session active for next {TOKEN_DURATION_SECONDS / 60} minutes.")

    if args.reset:
        if not auth_exists():
            print("Set a Master password first using -init.")
            return
        if not authenticate():
            return

        old_fernet_key=load_fernet_key_from_token()
        if not old_fernet_key:
            print("Session invalid or corrupted. Re-authentication required.")
            clear_token()
            return

        try:
            vault = load_encrypted_vault(old_fernet_key)
        except InvalidToken:
            print("Failed to decrypt vault: Invalid or expired session.")
            return
        except FileNotFoundError:
            print("Vault file not found.")
            return
        except json.JSONDecodeError:
            print("Vault file is corrupted or not in JSON format.")
            return

        print("Reset your master password:")
        while True:
            new_pw1 = getpass.getpass("Set new master password: ")
            new_pw2 = getpass.getpass("Confirm password: ")
            if new_pw1 == new_pw2:
                new_salt = secrets.token_bytes(SALT_SIZE)
                new_hash = hash_master_password(new_pw1, new_salt)
                save_master_password(new_hash)

                new_fernet_key = derive_fernet_key(new_pw1, new_salt)
                if save_encrypted_vault(vault, new_fernet_key):
                    print("Password added successfully.")
                else:
                    print("Failed to save password.")

                clear_token()
                print("Master password changed successfully.")
                return
            else:
                print("Passwords do not match. Try again.")

    #Add a new password
    if args.add:
        result = load_authenticated_vault()
        if not result:
            return
        vault, fernet_key = result

        if args.add is True:
            service = input("Enter service name (e.g., gmail): ").strip().lower()
            username = input("Enter username/email: ").strip()
            password = getpass.getpass("Enter password (leave blank to generate one): ").strip()
            if not password:
                password = generate_password()
                pyperclip.copy(password)
                print("Copied to clipboard.")
        else:
            parts = args.add.split(",")
            if len(parts) != 3:
                print("Invalid input format. Use: service,username,password")
                return
            service, username, password = map(str.strip, parts)
            service = service.lower()

        if service not in vault:
            vault[service] = {}
        if username in vault[service]:
            print("Entry already exists for this service and username.")
            return

        vault[service][username] = password
        if save_encrypted_vault(vault, fernet_key):
            print("Password added successfully.")
        else:
            print("Failed to save password.")

    # Fetch a stored password
    if args.fetch is not None:
        result = load_authenticated_vault()
        if not result:
            return
        vault, fernet_key = result

        service = None

        username = None

        # Handle input cases
        if args.fetch is True:
            # No input: interactive service + username prompt
            if not vault:
                print("Vault is empty.")
                return
            print("Available services:")
            for svc in vault:
                print(" -", svc)
            service = input("Enter service: ").strip().lower()
            if service not in vault:
                print("Invalid service name.")
                return
            print(f"Available usernames for '{service}':")
            for user in vault[service]:
                print(" -", user)
            username = input("Enter username/email: ").strip()

        else:
            # Argument passed
            parts = [part.strip() for part in args.fetch.split(",")]
            if len(parts) == 1:
                service = parts[0].lower()
                if service not in vault:
                    print("No such service in vault.")
                    return
                print(f"Available usernames for '{service}':")
                for user in vault[service]:
                    print(" -", user)
                username = input("Enter username/email: ").strip()
            elif len(parts) == 2:
                service, username = map(str.strip, parts)
                service = service.lower()
            else:
                print("Invalid input format. Use: service,username")
                return

        # Final check and retrieval
        if service not in vault or username not in vault[service]:
            print("No entry found for the given service and username.")
            return

        password = vault[service][username]
        pyperclip.copy(password)
        print("Password copied to clipboard.")
        if args.show:
            print(f"Password for {username} on {service}: {password}")

    # Remove a stored password
    if args.remove:
        result = load_authenticated_vault()
        if not result:
            return
        vault, fernet_key = result

        if not vault:
            print("Vault is empty.")
            return

        service = input("Enter service name to remove from: ").strip().lower()
        username = input("Enter username/email to remove: ").strip()

        if service not in vault or username not in vault[service]:
            print("No entry found for the given service and username.")
            return

        confirm = input(
            f"Are you sure you want to delete the password for {username} on {service}? (y/n): ").strip().lower()
        if confirm != 'y':
            print("Operation cancelled.")
            return

        del vault[service][username]
        if not vault[service]:
            del vault[service]

        if save_encrypted_vault(vault, fernet_key):
            print("Password entry removed successfully.")
        else:
            print("Password entry removal FAILED.")



    # Edit an existing password entry (service, username, or password)
    if args.edit:
        result = load_authenticated_vault()
        if not result:
            return
        vault, fernet_key = result

        if not vault:
            print("Vault is empty.")
            return

        service = input("Enter current service name: ").strip().lower()
        username = input("Enter current username/email: ").strip()

        if service not in vault or username not in vault[service]:
            print("No entry found for the given service and username.")
            return

        print("\n--- Leave blank to keep current value ---")
        new_service = input(f"New service name (current: {service}): ").strip().lower()
        new_username = input(f"New username/email (current: {username}): ").strip()
        new_password = getpass.getpass("New password (leave blank to generate): ").strip()

        new_service = new_service if new_service else service
        new_username = new_username if new_username else username
        if not new_password:
            new_password = generate_password()
            print(f"Generated password: {new_password}")
            pyperclip.copy(new_password)
            print("Copied to clipboard.")

        if new_service != service or new_username != username:
            del vault[service][username]
            if not vault[service]:
                del vault[service]

        if new_service not in vault:
            vault[new_service] = {}

        vault[new_service][new_username] = new_password
        if save_encrypted_vault(vault, fernet_key):
            print("Entry updated successfully.")
        else:
            print("Entry update FAILED.")



    #list all passwords
    # Summary View
    if args.list_summary:
        result = load_authenticated_vault()
        if not result:
            return
        vault, _ = result

        if not vault:
            print("Vault is empty.")
            return

        total_services = len(vault)
        total_accounts = sum(len(users) for users in vault.values())

        print("\n--- Vault Summary ---")
        print(f"Total Services  : {total_services}")
        print(f"Total Accounts  : {total_accounts}")

    # Expanded View
    elif args.list_expanded:
        result = load_authenticated_vault()
        if not result:
            return
        vault, _ = result

        if not vault:
            print("Vault is empty.")
            return

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

    if args.version:
        print(f"Pasman version {PASMAN_VERSION}")
        return

    if args.export:
        if not auth_exists():
            print("Set a Master password first using -init.")
            return
        export_vault(args.export)
        return

    if args.import_path:
        if not auth_exists():
            print("Set a Master password first using -init.")
            return
        if not token_is_valid():
            if not authenticate():
                return

        fernet_key = load_fernet_key_from_token()
        if not fernet_key:
            print("Session invalid or corrupted. Re-authentication required.")
            clear_token()
            return

        import_vault(args.import_path, fernet_key)
        return

    if args.import_txt:
        if not auth_exists():
            print("Set a Master password first using -init.")
            return
        if not token_is_valid():
            if not authenticate():
                return

        fernet_key = load_fernet_key_from_token()
        if not fernet_key:
            print("Session invalid or corrupted. Re-authentication required.")
            clear_token()
            return
        import_txt_file(args.import_txt, fernet_key)
    return


if __name__ == "__main__":
    main()
