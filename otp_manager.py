# Standard library imports
import base64
import calendar
import datetime
import getpass
import json
import os
import secrets
from typing import Dict, Generator, List, Optional, Tuple

# Third-party library imports
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Configuration Management ---

CONFIG_FILENAME = "otp_config.json"
DEFAULT_CONFIG = {"working_directory": os.path.expanduser("~")}


def get_script_dir() -> str:
    """Returns the directory where this script is located."""
    return os.path.dirname(os.path.abspath(__file__))


def load_config() -> dict:
    """Loads the config from the script directory."""
    config_path = os.path.join(get_script_dir(), CONFIG_FILENAME)
    if not os.path.exists(config_path):
        return DEFAULT_CONFIG.copy()

    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load config ({e}). Using defaults.")
        return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> None:
    """Saves the config to the script directory."""
    config_path = os.path.join(get_script_dir(), CONFIG_FILENAME)
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
        print(f"Configuration saved to {config_path}")
    except Exception as e:
        print(f"Error saving config: {e}")


def get_working_dir(config: dict) -> str:
    """Retrieves and validates the working directory from config."""
    path = config.get("working_directory", ".")
    if not os.path.exists(path):
        try:
            os.makedirs(path)
            print(f"Created working directory: {path}")
        except OSError:
            print(
                f"Warning: Working directory '{path}' invalid. Using current directory."
            )
            return "."
    return path


# --- Core Cryptography Logic (Pure Functions) ---


def _derive_aes_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Derives a 256-bit AES key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def _perform_otp_xor(data_bytes: bytes, key_segment_bytes: bytes) -> bytes:
    """Performs the OTP XOR operation."""
    if len(data_bytes) > len(key_segment_bytes):
        raise ValueError("Data cannot be longer than key segment.")
    return bytes(d ^ k for d, k in zip(data_bytes, key_segment_bytes))


# --- OTP Key Management ---


def generate_date_range(
    start_date: datetime.date, num_years: int
) -> Generator[datetime.date, None, None]:
    """Generates dates for the specified number of years."""
    # Approximate end date calculation
    end_year = start_date.year + num_years
    try:
        end_date = start_date.replace(year=end_year)
    except ValueError:  # Handle leap year edge case (Feb 29 -> Feb 28)
        end_date = start_date.replace(year=end_year, day=28)

    # Subtract one day to make it exactly num_years
    end_date = end_date - datetime.timedelta(days=1)

    curr = start_date
    while curr <= end_date:
        yield curr
        curr += datetime.timedelta(days=1)


def generate_otp_key_dictionary(
    start_date: datetime.date, num_years: int, bytes_per_key: int
) -> Dict[str, bytes]:
    return {
        d.isoformat(): secrets.token_bytes(bytes_per_key)
        for d in generate_date_range(start_date, num_years)
    }


def save_otp_dictionary(
    otp_dict: Dict[str, bytes], filepath: str, password: str
) -> None:
    # 1. Base64 encode values for JSON serialization
    serializable = {d: base64.b64encode(k).decode("ascii") for d, k in otp_dict.items()}
    json_data = json.dumps(serializable).encode("utf-8")

    # 2. Encrypt the JSON blob
    salt, nonce = os.urandom(16), os.urandom(12)
    aes_key = _derive_aes_key(password, salt)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, json_data, None)

    # 3. Write Salt + Nonce + Ciphertext
    with open(filepath, "wb") as f:
        f.write(salt + nonce + ciphertext)


def load_otp_dictionary(filepath: str, password: str) -> Dict[str, bytes]:
    with open(filepath, "rb") as f:
        data = f.read()

    salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
    aes_key = _derive_aes_key(password, salt)
    aesgcm = AESGCM(aes_key)

    plaintext_json = aesgcm.decrypt(nonce, ciphertext, None)
    serializable = json.loads(plaintext_json.decode("utf-8"))

    return {d: base64.b64decode(k) for d, k in serializable.items()}


# --- File I/O for Messages ---


def encrypt_file_hardcoded(
    working_dir: str, otp_dict: Dict[str, bytes], date_iso: str, position: int
) -> int:
    input_path = os.path.join(working_dir, "message_input.txt")
    output_path = os.path.join(working_dir, "encrypted_message.txt")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Missing input file: {input_path}")

    with open(input_path, "r", encoding="utf-8") as f:
        plaintext = f.read().encode("utf-8")

    if date_iso not in otp_dict:
        raise KeyError(f"Date {date_iso} not found in dictionary.")

    key_data = otp_dict[date_iso]
    if position + len(plaintext) > len(key_data):
        raise ValueError(
            f"Key exhausted for {date_iso}. Need {len(plaintext)} bytes, found {len(key_data) - position}."
        )

    key_segment = key_data[position : position + len(plaintext)]
    ciphertext = _perform_otp_xor(plaintext, key_segment)

    with open(output_path, "wb") as f:
        f.write(ciphertext)

    return len(plaintext)


def decrypt_file_hardcoded(
    working_dir: str, otp_dict: Dict[str, bytes], date_iso: str, position: int
) -> int:
    input_path = os.path.join(working_dir, "encrypted_message.txt")
    output_path = os.path.join(working_dir, "decrypted_message.txt")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Missing encrypted file: {input_path}")

    with open(input_path, "rb") as f:
        ciphertext = f.read()

    if date_iso not in otp_dict:
        raise KeyError(f"Date {date_iso} not found in dictionary.")

    key_data = otp_dict[date_iso]
    if position + len(ciphertext) > len(key_data):
        raise ValueError(f"Key exhausted for {date_iso}.")

    key_segment = key_data[position : position + len(ciphertext)]
    plaintext_bytes = _perform_otp_xor(ciphertext, key_segment)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(plaintext_bytes.decode("utf-8"))

    return len(ciphertext)


# --- UI Helpers ---


def get_valid_filename(prompt: str) -> str:
    while True:
        name = input(prompt).strip()
        if name and not os.path.sep in name:  # Ensure it's just a filename, not a path
            return name
        print("Invalid filename. Please do not include folders/slashes.")


def get_int_input(prompt: str, min_val: int = 0) -> int:
    while True:
        try:
            val = int(input(prompt))
            if val >= min_val:
                return val
            print(f"Number must be >= {min_val}")
        except ValueError:
            print("Invalid number.")


def get_date_input(prompt: str) -> datetime.date:
    while True:
        d_str = input(f"{prompt} (YYYY-MM-DD): ").strip()
        try:
            return datetime.datetime.strptime(d_str, "%Y-%m-%d").date()
        except ValueError:
            print("Invalid format.")


# --- Main Application ---


def run_otp_system():
    config = load_config()
    loaded_dict: Optional[Dict[str, bytes]] = None

    while True:
        working_dir = get_working_dir(config)
        print("\n" + "=" * 40)
        print(f"OTP MANAGER | Working Dir: {working_dir}")
        print("=" * 40)
        print("1. Set Working Directory")
        print("2. Generate New Keys")
        print("3. Load Key Dictionary")
        print("4. Encrypt (message_input.txt -> encrypted_message.txt)")
        print("5. Decrypt (encrypted_message.txt -> decrypted_message.txt)")
        print("6. Exit")

        choice = input("\nSelect Option: ").strip()

        try:
            if choice == "1":
                new_dir = input("Enter new working directory path: ").strip()
                if os.path.isdir(new_dir):
                    config["working_directory"] = os.path.abspath(new_dir)
                    save_config(config)
                else:
                    print("Directory does not exist. Please create it first.")

            elif choice == "2":
                fname = get_valid_filename(
                    "Enter filename for new keys (e.g. keys_2025.enc): "
                )
                full_path = os.path.join(working_dir, fname)

                if os.path.exists(full_path):
                    if input("File exists. Overwrite? (y/n): ").lower() != "y":
                        continue

                start = get_date_input("Start Date")
                years = get_int_input("Number of Years: ", 1)
                size = get_int_input("Bytes per key (e.g. 50000): ", 1)
                pw = getpass.getpass("Encryption Password: ")
                confirm = getpass.getpass("Confirm Password: ")

                if pw != confirm:
                    print("Passwords do not match.")
                    continue

                print("Generating...")
                new_dict = generate_otp_key_dictionary(start, years, size)
                save_otp_dictionary(new_dict, full_path, pw)
                print(f"Keys saved to {full_path}")
                loaded_dict = new_dict

            elif choice == "3":
                # List files in working dir for convenience
                print("\nFiles in directory:")
                for f in os.listdir(working_dir):
                    if f.endswith(".enc") or f.endswith(".json") or f.endswith(".key"):
                        print(f" - {f}")

                fname = get_valid_filename("Enter dictionary filename: ")
                full_path = os.path.join(working_dir, fname)

                if not os.path.exists(full_path):
                    print("File not found.")
                    continue

                pw = getpass.getpass("Password: ")
                loaded_dict = load_otp_dictionary(full_path, pw)
                print(f"Loaded {len(loaded_dict)} keys.")

            elif choice in ["4", "5"]:
                if not loaded_dict:
                    print("Please Load Keys (Option 3) first.")
                    continue

                date_iso = get_date_input("Date of message").isoformat()
                pos = get_int_input("Start Position: ")

                if choice == "4":
                    processed = encrypt_file_hardcoded(
                        working_dir, loaded_dict, date_iso, pos
                    )
                    print(f"Encrypted {processed} bytes.")
                    print(f"Next available position for {date_iso}: {pos + processed}")
                else:
                    processed = decrypt_file_hardcoded(
                        working_dir, loaded_dict, date_iso, pos
                    )
                    print(f"Decrypted {processed} bytes.")

            elif choice == "6":
                print("Exiting.")
                break

        except Exception as e:
            print(f"\nERROR: {e}")
            input("Press Enter to continue...")


if __name__ == "__main__":
    run_otp_system()
