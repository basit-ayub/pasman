# Pasman

Pasman is a local command-line password manager written in Python. It stores your account passwords in an encrypted vault on your computer. Use it to add, find, edit, remove, import, and export credentials from a terminal.

## How password storage works

Pasman keeps its files in your home directory by default. On Linux and macOS, they are hidden files in `~`:

| File | What it contains |
| --- | --- |
| `~/.pasman_vault.json` | Your service names, usernames, and passwords, encrypted with Fernet. |
| `~/.pasman_auth.bin` | A random salt and a PBKDF2-HMAC-SHA256 verifier for your master password. It does not store the master password itself. |
| `~/.pasman_token.txt` | A temporary session timestamp and the derived vault encryption key. This key is readable from the file while the session is active. |

The master password derives the key used to encrypt and decrypt the vault. Pasman does not sync your data to a server. The session lasts three minutes; use `quit` to clear it sooner. Anyone with access to your account while a session token exists can read that token and access the vault, so use Pasman only in a trusted local account and log out on shared devices. Losing your master password means Pasman cannot decrypt the vault.

Set `PASMAN_DIR` to use another directory for all three files. Choose a directory you trust and protect its backups; cloud syncing also copies the session token if it is present.

## Requirements and installation

- Python 3
- The `cryptography` and `pyperclip` Python packages

From the project directory, install the dependencies and start Pasman:

```bash
python -m pip install cryptography pyperclip
python pasman.py init
```

On first run, `init` asks you to set and confirm a master password. On later runs, it unlocks the existing vault. Enter the master password when prompted; input is hidden as you type. Keep it somewhere safe because there is no recovery mechanism.

To store the vault in a different directory, set `PASMAN_DIR` before running Pasman:

```bash
export PASMAN_DIR="$HOME/.local/share/pasman"
python pasman.py init
```

In Windows PowerShell, set it for the current terminal with `$env:PASMAN_DIR = "$HOME\pasman-data"`.

## Commands

Run commands from the project directory with `python pasman.py`. Most vault commands prompt for your master password when the session is missing or expired. If service or username arguments are omitted, commands that select an existing entry prompt you interactively.

| Command | What it does | Example |
| --- | --- | --- |
| `init` | Create the vault and set a master password on first use, or unlock an existing vault. | `python pasman.py init` |
| `add [service] [username]` | Add an account. Enter a password when prompted, or leave it blank to generate one. | `python pasman.py add github you@example.com` |
| `fetch [service] [username]` | Copy an account password to the clipboard. Add `--show` to also print it in the terminal. | `python pasman.py fetch github you@example.com --show` |
| `edit [service] [username]` | Change an account's service, username, or password. | `python pasman.py edit github you@example.com` |
| `remove [service] [username]` | Remove an account after confirmation. | `python pasman.py remove github you@example.com` |
| `list` | Show the number of services and accounts in the vault. | `python pasman.py list` |
| `list --expanded` or `list -e` | Show service names and usernames as well as the totals. Passwords are not listed. | `python pasman.py list --expanded` |
| `create` | Generate a password and copy it to the clipboard without saving it. | `python pasman.py create` |
| `reset` | Verify your current master password, then set a new one and re-encrypt the vault. | `python pasman.py reset` |
| `quit` | Clear the current session token and log out. | `python pasman.py quit` |
| `export <path>` | Write an encrypted vault backup to a file. | `python pasman.py export ./pasman-backup.bin` |
| `import <path>` | Decrypt a Pasman export using that export's master password, then merge its entries into your current vault. Existing matching service and username pairs are skipped. | `python pasman.py import ./pasman-backup.bin` |
| `import-txt <path>` | Import comma-separated `service,username,password` rows from a UTF-8 CSV file. Existing entries are skipped. | `python pasman.py import-txt ./passwords.csv` |
| `--help` | Show available commands and options. | `python pasman.py --help` |
| `--version` | Show the Pasman version. | `python pasman.py --version` |

Fetch copies the password to your clipboard. If clipboard support is unavailable, Pasman asks whether to display the password in the terminal. `import-txt` reads passwords in plain text, so use a trusted source file and remove it securely when you no longer need it.

## Technology

Pasman uses Python's command-line argument parser and standard libraries for terminal prompts, password generation, JSON, CSV, and file handling. The `cryptography` package provides Fernet authenticated encryption and PBKDF2-HMAC-SHA256 key derivation. The `pyperclip` package provides clipboard access. Interactive selection uses `readline` when available.
