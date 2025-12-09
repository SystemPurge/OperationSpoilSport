# Standard library imports
import base64
import calendar
import datetime
import json
import os
import secrets
import getpass # For securely getting password input without echoing
from typing import Dict, Iterable, Generator, Optional, Tuple, Union

# Third-party library imports
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# GUI stuff
import tkinter
from tkinter import filedialog
from typing import List, Tuple, Optional

def get_filepath_from_dialog(
    dialog_mode: str,
    title: str,
    filetypes: List[Tuple[str, str]],
    initialdir: Optional[str] = None,
    defaultextension: Optional[str] = None
) -> str:
    """
    Displays a Tkinter file dialog to get a filepath from the user.

    Args:
        dialog_mode: Either "open" to select an existing file, or "save"
                     to select a file for saving.
        title: The title for the dialog window.
        filetypes: A list of (label, pattern) tuples, e.g.,
                   [("Text files", "*.txt"), ("All files", "*.*")].
        initialdir: The directory the dialog should open in initially.
                    If None, a default directory is used.
        defaultextension: The default extension to append if the user doesn't
                          provide one (for save dialogs, e.g., ".txt").

    Returns:
        The absolute path to the selected file as a string, or an empty
        string if the user cancels the dialog or an error occurs.
    """
    filepath = ""
    root = None  # Initialize root to None for the finally block
    try:
        root = tkinter.Tk()
        root.withdraw()  # Hide the main Tkinter window

        if dialog_mode == "open":
            filepath = filedialog.askopenfilename(
                title=title,
                initialdir=initialdir,
                filetypes=filetypes,
                parent=root # Explicitly set parent for better dialog behavior
            )
        elif dialog_mode == "save":
            filepath = filedialog.asksaveasfilename(
                title=title,
                initialdir=initialdir,
                filetypes=filetypes,
                defaultextension=defaultextension,
                parent=root # Explicitly set parent
            )
        else:
            # In a more robust implementation, this might raise a ValueError.
            # For now, print to stderr or log, and return empty path.
            print(f"Error: Invalid dialog_mode '{dialog_mode}'. Must be 'open' or 'save'.")
            # Consider raising ValueError("Invalid dialog_mode. Must be 'open' or 'save'.")
            return ""

    except tkinter.TclError as e:
        # This can happen if tkinter is not available or fails to initialize
        # (e.g. no display server like on a headless system)
        print(f"Tkinter error: {e}. Unable to display file dialog.")
        print("Ensure you have a display environment (e.g., X11, Wayland, Aqua).")
        # Fallback to asking for input in console, or simply return empty.
        # For this example, we'll just return an empty string.
        return "" # Indicates failure or cancellation
    except Exception as e:
        # Catch any other unexpected errors during dialog display
        print(f"An unexpected error occurred with the file dialog: {e}")
        return "" # Indicates failure
    finally:
        if root:
            # Ensure the root window is destroyed to free resources.
            # This is important if the function is called multiple times.
            root.destroy()

    # filedialog returns an empty string if cancelled, or a tuple on some older versions (rare).
    # We ensure it's always a string.
    return str(filepath) if filepath else ""


def generate_date_range(start_date: datetime.date, end_date: datetime.date) -> Generator[datetime.date, None, None]:
    """
    Generates a sequence of dates from start_date to end_date, inclusive.

    Args:
        start_date: The starting date.
        end_date: The ending date.

    Yields:
        datetime.date objects from start_date up to end_date.
    """
    if start_date > end_date:
        # Return an empty generator if start is after end
        return
        # Or alternatively: raise ValueError("Start date must not be after end date")

    current_date = start_date
    while current_date <= end_date:
        yield current_date
        # Move to the next day
        current_date += datetime.timedelta(days=1)

def generate_otp_key_dictionary(
    start_date: datetime.date,
    num_years: int,
    bytes_per_key: int
) -> Dict[str, bytes]:
    """
    Generates a dictionary of One-Time Pad keys for a specified period.

    Each key is a string of cryptographically secure random bytes.
    The dictionary keys are date strings in ISO 8601 format ('YYYY-MM-DD').

    Args:
        start_date: The first date for which to generate a key.
        num_years: The number of years into the future to generate keys for.
        bytes_per_key: The number of random bytes each daily key should contain.

    Returns:
        A dictionary mapping date strings ('YYYY-MM-DD') to the
        corresponding random key bytes.

    Raises:
        ValueError: If bytes_per_key is not positive.
        ValueError: If num_years is not positive.
        OverflowError: If the date range extends beyond datetime.MAXYEAR.
    """
    if bytes_per_key <= 0:
        raise ValueError("bytes_per_key must be positive")
    if num_years <= 0:
        raise ValueError("num_years must be positive")

    # Calculate the approximate number of days
    # Adding leap days provides a more accurate duration for the period
    # Note: calendar.leapdays counts leap days *between* year1 and year2 (exclusive of year2).
    # To get the count for the full num_years duration starting from start_date,
    # we check the range start_date.year to start_date.year + num_years.
    try:
        num_leap_days = calendar.leapdays(start_date.year, start_date.year + num_years)
        # Adjust if the start date is after Feb 28 in a leap year, or
        # if the end date is before Feb 29 in a leap year. This simple calculation
        # is generally good enough for duration but exact end date is better.
    except ValueError:
        # Handle cases where year calculation might exceed valid ranges, though
        # date calculation below is the primary check.
         raise OverflowError("Year range exceeds system limits")


    # Calculate the end date reliably
    # Adding timedelta directly handles month/year rollovers and leap years
    # We want num_years worth of keys, so we need N*365 + leap days.
    # Simpler: Calculate the target end date directly.
    # Be careful with Feb 29. If start is Feb 29, adding years might fail.
    try:
        # Calculate nominal end date year
        target_end_year = start_date.year + num_years
        # Try to create the date. If start_date is Feb 29 and target year is not leap, adjust.
        end_month = start_date.month
        end_day = start_date.day
        if start_date.month == 2 and start_date.day == 29 and not calendar.isleap(target_end_year):
            end_day = 28 # Adjust to Feb 28

        # The range should include start_date and go up to (but not including)
        # the date exactly num_years later. So the last day is the day *before*
        # that anniversary date.
        anniversary_date = datetime.date(target_end_year, end_month, end_day)
        end_date_inclusive = anniversary_date - datetime.timedelta(days=1)

    except OverflowError:
         raise OverflowError(f"Resulting date range exceeds maximum representable date ({datetime.MAXYEAR})")
    except ValueError as e:
         # General catch for other date calculation issues
         raise ValueError(f"Error calculating end date: {e}")


    if end_date_inclusive < start_date:
         # This shouldn't happen with positive num_years, but good to check
         return {} # Or raise error

    # --- Functional approach using a dictionary comprehension ---
    key_dict = {
        current_date.isoformat(): secrets.token_bytes(bytes_per_key)
        for current_date in generate_date_range(start_date, end_date_inclusive)
    }

    return key_dict


# --- Component 2: Core OTP Operation (Helper) ---

def _perform_otp_xor(data_bytes: bytes, key_segment_bytes: bytes) -> bytes:
    """
    Performs the OTP XOR operation between data and a key segment.

    Args:
        data_bytes: The data to be XORed (can be plaintext or ciphertext bytes).
        key_segment_bytes: The segment of the OTP key to use.

    Returns:
        The result of the XOR operation as bytes.

    Raises:
        ValueError: If the data is longer than the provided key segment.
    """
    if len(data_bytes) > len(key_segment_bytes):
        raise ValueError("Data to be XORed cannot be longer than the key segment.")

    # Perform byte-wise XOR for the length of data_bytes
    # The key_segment_bytes might be longer, but only the portion
    # corresponding to the data_bytes length will be used by zip.
    return bytes(d ^ k for d, k in zip(data_bytes, key_segment_bytes))

# --- Component 1: OTP Dictionary Persistence (with AES-GCM Encryption) ---

# Constants for Encryption
_SALT_SIZE = 16  # bytes
_NONCE_SIZE = 12  # bytes for AES-GCM (96 bits is recommended)
_PBKDF2_ITERATIONS = 200_000  # Increased for better security, adjust based on performance needs
_AES_KEY_SIZE = 32  # bytes, for AES-256

def _derive_aes_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit AES encryption key from a password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password: The user-provided password.
        salt: A random salt (typically _SALT_SIZE bytes).

    Returns:
        The derived AES key ( _AES_KEY_SIZE bytes).
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if not salt or len(salt) != _SALT_SIZE:
        raise ValueError(f"Salt must be {_SALT_SIZE} bytes long.")

    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_SIZE,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password_bytes)

def save_otp_dictionary(
    otp_dict: Dict[str, bytes],
    filepath: str,
    password: str
) -> None:
    """
    Saves the OTP key dictionary to a file, encrypted with AES-256-GCM.

    The OTP dictionary's byte values are first Base64 encoded before JSON serialization.
    The resulting JSON data is then encrypted.
    File format: salt (16 bytes) | nonce (12 bytes) | AES-GCM ciphertext with tag.

    Args:
        otp_dict: The OTP dictionary to save (maps date strings to key bytes).
        filepath: The path to the file where the dictionary will be saved.
        password: Password to encrypt the dictionary file.

    Raises:
        ValueError: If the password is empty.
        IOError: If file writing fails.
        Exception: For other unexpected errors during encryption.
    """
    if not password:
        raise ValueError("A password is required to save the encrypted OTP dictionary.")

    try:
        # 1. Prepare dictionary for serialization (Base64 encode byte values)
        serializable_dict: Dict[str, str] = {
            date_str: base64.b64encode(key_bytes).decode('ascii')
            for date_str, key_bytes in otp_dict.items()
        }

        # 2. Serialize to JSON string, then encode to UTF-8 bytes
        json_data_bytes = json.dumps(serializable_dict, indent=2).encode('utf-8')

        # 3. Generate random salt
        salt = os.urandom(_SALT_SIZE)

        # 4. Derive AES key
        aes_key = _derive_aes_key(password, salt)

        # 5. Generate random nonce
        nonce = os.urandom(_NONCE_SIZE)

        # 6. Initialize AESGCM
        aesgcm = AESGCM(aes_key)

        # 7. Encrypt data
        encrypted_data_with_tag = aesgcm.encrypt(nonce, json_data_bytes, None) # No AAD

        # 8. Write salt + nonce + encrypted_data_with_tag to file
        with open(filepath, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(encrypted_data_with_tag)

    except FileNotFoundError:
        raise IOError(f"Error: The directory for filepath '{filepath}' may not exist or path is invalid.")
    except PermissionError:
        raise IOError(f"Error: Permission denied to write to '{filepath}'.")
    except Exception as e:
        # Catch other potential errors (e.g., from cryptography library)
        # In a real app, more specific error handling or logging would be beneficial
        raise Exception(f"An unexpected error occurred during saving: {e}")


def load_otp_dictionary(
    filepath: str,
    password: str
) -> Dict[str, bytes]:
    """
    Loads and decrypts an OTP key dictionary from an AES-256-GCM encrypted file.

    Args:
        filepath: The path to the encrypted file.
        password: Password to decrypt the dictionary file.

    Returns:
        The loaded OTP dictionary (maps date strings to key bytes).

    Raises:
        FileNotFoundError: If the filepath does not exist.
        IOError: For other file reading issues.
        ValueError: If password is empty, or file format is incorrect (e.g. too short).
        InvalidTag: If decryption fails (wrong password or corrupted file).
        json.JSONDecodeError: If the decrypted content is not valid JSON.
        TypeError: If the JSON structure is not as expected.
        Exception: For other unexpected errors during loading/decryption.
    """
    if not password:
        raise ValueError("A password is required to load the encrypted OTP dictionary.")

    try:
        # 1. Read the entire encrypted blob from filepath
        with open(filepath, 'rb') as f:
            encrypted_blob = f.read()

        # Validate file size (must be at least salt + nonce + 1 byte for data/tag)
        if len(encrypted_blob) < _SALT_SIZE + _NONCE_SIZE + 1:
            raise ValueError("Encrypted file is too short to be valid.")

        # 2. Extract salt
        salt = encrypted_blob[:_SALT_SIZE]
        # 3. Extract nonce
        nonce = encrypted_blob[_SALT_SIZE : _SALT_SIZE + _NONCE_SIZE]
        # 4. Extract encrypted data with tag
        encrypted_data_with_tag = encrypted_blob[_SALT_SIZE + _NONCE_SIZE:]

        # 5. Derive AES key
        aes_key = _derive_aes_key(password, salt)

        # 6. Initialize AESGCM
        aesgcm = AESGCM(aes_key)

        # 7. Decrypt data
        # InvalidTag will be raised by .decrypt() if authentication fails (wrong password/corrupt)
        json_data_bytes = aesgcm.decrypt(nonce, encrypted_data_with_tag, None) # No AAD

        # 8. Decode UTF-8 bytes to JSON string, then parse
        serializable_dict: Dict[str, str] = json.loads(json_data_bytes.decode('utf-8'))

        # 9. Convert Base64 encoded strings back to bytes
        otp_dict: Dict[str, bytes] = {
            date_str: base64.b64decode(b64_encoded_key)
            for date_str, b64_encoded_key in serializable_dict.items()
        }

        # Basic validation of loaded dictionary structure
        if not isinstance(otp_dict, dict):
             raise TypeError("Decrypted data did not result in a dictionary.")
        for key, value in otp_dict.items():
            if not isinstance(key, str) or not isinstance(value, bytes):
                raise TypeError("OTP dictionary format is incorrect after decryption. Expected Dict[str, bytes].")


        return otp_dict

    except FileNotFoundError:
        raise FileNotFoundError(f"Error: Encrypted OTP dictionary file not found at '{filepath}'.")
    except PermissionError:
        raise IOError(f"Error: Permission denied to read from '{filepath}'.")
    except InvalidTag:
        # This is crucial for security: indicates wrong password or tampered file
        raise InvalidTag("Decryption failed: Incorrect password or corrupted file.")
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Failed to decode JSON from decrypted data: {e.msg}", e.doc, e.pos)
    except (TypeError, base64.binascii.Error) as e: # Catch B64 decoding errors or type errors from dict construction
        raise TypeError(f"Failed to correctly parse the decrypted dictionary structure or Base64 content: {e}")
    except ValueError as e: # Catch ValueErrors from _derive_aes_key or file size check
        raise ValueError(f"Configuration or file format error: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred during loading: {e}")
#    --------------------------------------
# from typing import Dict # Assuming other necessary imports like os, json, base64, cryptography, _perform_otp_xor are in the same file

# --- Component 3: Message Encryption ---

def encrypt_message_from_file(
    plaintext_filepath: str,
    ciphertext_filepath: str,
    otp_dict: Dict[str, bytes],
    date_iso: str,
    position: int
) -> int:
    """
    Encrypts a plaintext message from a file using a specified key from the OTP dictionary.

    The plaintext file is assumed to be UTF-8 encoded.
    The ciphertext is saved as raw bytes.

    Args:
        plaintext_filepath: Path to the .txt file containing the UTF-8 plaintext.
        ciphertext_filepath: Path where the encrypted output (raw bytes) will be saved.
        otp_dict: The loaded OTP dictionary.
        date_iso: The ISO 8601 date string (e.g., "2025-05-17") for the key to use.
        position: The starting byte position within the selected day's OTP key.
                  Must be non-negative.

    Returns:
        The length of the plaintext message in bytes (which is also the length of
        the key segment used). This helps in tracking the next available position.

    Raises:
        FileNotFoundError: If the plaintext_filepath does not exist.
        PermissionError: If there's a permission issue with file operations.
        IOError: For other general I/O errors.
        KeyError: If the specified date_iso is not found in the otp_dict.
        ValueError: If the position is negative, or if the message is too long for
                    the available key segment at the specified position/date.
        UnicodeDecodeError: If the input file is not valid UTF-8 (less likely for encryption
                            but good to be aware of file encodings).
    """
    try:
        # 1. Read plaintext from plaintext_filepath (assuming UTF-8)
        with open(plaintext_filepath, 'r', encoding='utf-8') as f:
            plaintext_string = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: Plaintext file not found at '{plaintext_filepath}'.")
    except PermissionError:
        raise PermissionError(f"Error: Permission denied to read from '{plaintext_filepath}'.")
    except UnicodeDecodeError as e:
        raise UnicodeDecodeError(f"Error decoding plaintext file '{plaintext_filepath}'. Ensure it is UTF-8 encoded. Details: {e}")
    except IOError as e:
        raise IOError(f"Error reading plaintext file '{plaintext_filepath}': {e}")

    # 2. Encode plaintext string to bytes (UTF-8)
    plaintext_bytes = plaintext_string.encode('utf-8')
    message_length = len(plaintext_bytes)

    if message_length == 0:
        # Handle empty message case: write an empty ciphertext file.
        try:
            with open(ciphertext_filepath, 'wb') as f_out:
                f_out.write(b'')
            return 0
        except PermissionError:
            raise PermissionError(f"Error: Permission denied to write to '{ciphertext_filepath}'.")
        except IOError as e:
            raise IOError(f"Error writing empty ciphertext file '{ciphertext_filepath}': {e}")


    # 3. Validate position
    if position < 0:
        raise ValueError("Position cannot be negative.")

    # 4. Retrieve the daily_key from otp_dict using date_iso
    try:
        daily_key = otp_dict[date_iso]
    except KeyError:
        raise KeyError(f"Error: No OTP key found for date '{date_iso}'.")

    # 5. Validate key availability
    if not isinstance(daily_key, bytes):
        raise TypeError(f"Error: Key for date '{date_iso}' is not in bytes format.")

    if position + message_length > len(daily_key):
        raise ValueError(
            f"Message too long for available key segment. "
            f"Message length: {message_length}, Position: {position}, "
            f"Key length for date '{date_iso}': {len(daily_key)}."
        )

    # 6. Extract the required key segment
    key_segment_bytes = daily_key[position : position + message_length]

    # 7. Use _perform_otp_xor to encrypt
    # Assuming _perform_otp_xor is defined in the same scope/file
    ciphertext_bytes = _perform_otp_xor(plaintext_bytes, key_segment_bytes)

    # 8. Write the resulting ciphertext bytes to ciphertext_filepath
    try:
        with open(ciphertext_filepath, 'wb') as f_out:
            f_out.write(ciphertext_bytes)
    except PermissionError:
        raise PermissionError(f"Error: Permission denied to write to '{ciphertext_filepath}'.")
    except IOError as e:
        raise IOError(f"Error writing ciphertext file '{ciphertext_filepath}': {e}")

    # 9. Return message_length
    return message_length

# --- Component 4: Message Decryption ---

def decrypt_message_to_file(
    ciphertext_filepath: str,
    plaintext_filepath: str,
    otp_dict: Dict[str, bytes],
    date_iso: str,
    position: int
) -> int:
    """
    Decrypts a ciphertext message from a file using a specified key from the OTP dictionary.

    The ciphertext file is assumed to contain raw bytes.
    The decrypted plaintext is saved as a UTF-8 encoded .txt file.

    Args:
        ciphertext_filepath: Path to the file containing the raw byte ciphertext.
        plaintext_filepath: Path where the decrypted plaintext (UTF-8 .txt) will be saved.
        otp_dict: The loaded OTP dictionary.
        date_iso: The ISO 8601 date string (e.g., "2025-05-17") for the key to use.
        position: The starting byte position within the selected day's OTP key.
                  Must be non-negative.

    Returns:
        The length of the ciphertext message in bytes (which is also the length of
        the key segment used).

    Raises:
        FileNotFoundError: If the ciphertext_filepath does not exist.
        PermissionError: If there's a permission issue with file operations.
        IOError: For other general I/O errors.
        KeyError: If the specified date_iso is not found in the otp_dict.
        ValueError: If the position is negative, or if the ciphertext implies a key
                    segment larger than available at the specified position/date.
        UnicodeDecodeError: If the decrypted bytes do not form a valid UTF-8 string.
    """
    try:
        # 1. Read ciphertext_bytes from ciphertext_filepath
        with open(ciphertext_filepath, 'rb') as f:
            ciphertext_bytes = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: Ciphertext file not found at '{ciphertext_filepath}'.")
    except PermissionError:
        raise PermissionError(f"Error: Permission denied to read from '{ciphertext_filepath}'.")
    except IOError as e:
        raise IOError(f"Error reading ciphertext file '{ciphertext_filepath}': {e}")

    message_length = len(ciphertext_bytes)

    if message_length == 0:
        # Handle empty ciphertext case: write an empty plaintext file.
        try:
            with open(plaintext_filepath, 'w', encoding='utf-8') as f_out:
                f_out.write('')
            return 0
        except PermissionError:
            raise PermissionError(f"Error: Permission denied to write to '{plaintext_filepath}'.")
        except IOError as e:
            raise IOError(f"Error writing empty plaintext file '{plaintext_filepath}': {e}")

    # 2. Validate position
    if position < 0:
        raise ValueError("Position cannot be negative.")

    # 3. Retrieve the daily_key from otp_dict using date_iso
    try:
        daily_key = otp_dict[date_iso]
    except KeyError:
        raise KeyError(f"Error: No OTP key found for date '{date_iso}'.")

    # 4. Validate key availability
    if not isinstance(daily_key, bytes):
        raise TypeError(f"Error: Key for date '{date_iso}' is not in bytes format.")

    if position + message_length > len(daily_key):
        raise ValueError(
            f"Ciphertext implies a key segment larger than available. "
            f"Ciphertext length: {message_length}, Position: {position}, "
            f"Key length for date '{date_iso}': {len(daily_key)}."
        )

    # 5. Extract the required key segment
    key_segment_bytes = daily_key[position : position + message_length]

    # 6. Use _perform_otp_xor to decrypt
    # Assuming _perform_otp_xor is defined in the same scope/file
    decrypted_bytes = _perform_otp_xor(ciphertext_bytes, key_segment_bytes)

    # 7. Decode decrypted_bytes to a string (UTF-8)
    try:
        plaintext_string = decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise UnicodeDecodeError(
            f"Failed to decode decrypted bytes to UTF-8. "
            f"The key, position, or ciphertext might be incorrect, or the original message was not UTF-8. Details: {e}"
        )

    # 8. Write the plaintext string to plaintext_filepath
    try:
        with open(plaintext_filepath, 'w', encoding='utf-8') as f_out:
            f_out.write(plaintext_string)
    except PermissionError:
        raise PermissionError(f"Error: Permission denied to write to '{plaintext_filepath}'.")
    except IOError as e:
        raise IOError(f"Error writing plaintext file '{plaintext_filepath}': {e}")

    # 9. Return message_length
    return message_length

# ---------------------------------
# ------------------------------
# ----------------------------------
# -------------------------


# Assuming your existing functions (generate_otp_key_dictionary, save_otp_dictionary, etc.)
# and their necessary imports (json, base64, hashlib, cryptography) are already in the script.

# --- UI Helper Functions ---

def display_menu() -> None:
    """Prints the main menu options to the console."""
    print("\nOTP Encryption System")
    print("---------------------")
    print("1. Generate and Save New OTP Key Dictionary")
    print("2. Load OTP Key Dictionary from File")
    print("3. Encrypt Message from File")
    print("4. Decrypt Message to File")
    print("5. Exit")
    print("---------------------")

def press_enter_to_continue() -> None:
    """Pauses execution until the user presses Enter."""
    input("Press Enter to continue...")

def get_string_input(prompt: str) -> str:
    """
    Gets a non-empty string input from the user.

    Args:
        prompt: The message to display to the user.

    Returns:
        The string entered by the user, stripped of leading/trailing whitespace.
        Loops until a non-empty string is provided.
    """
    while True:
        user_input = input(prompt).strip()
        if user_input:
            return user_input
        else:
            print("Input cannot be empty. Please try again.")

def get_password_input(prompt: str = "Enter password: ") -> str:
    """
    Gets password input securely from the user (input is not echoed).

    Args:
        prompt: The message to display to the user.

    Returns:
        The password string entered by the user.
        Loops until a non-empty password is provided.
    """
    while True:
        password = getpass.getpass(prompt)
        if password:
            return password
        else:
            print("Password cannot be empty. Please try again.")

def get_int_input(
    prompt: str,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None
) -> int:
    """
    Gets an integer input from the user, with optional min/max validation.

    Args:
        prompt: The message to display to the user.
        min_val: Optional minimum acceptable value (inclusive).
        max_val: Optional maximum acceptable value (inclusive).

    Returns:
        The validated integer entered by the user.
        Loops until a valid integer within the specified range is provided.
    """
    while True:
        try:
            user_input_str = input(prompt).strip()
            user_input_int = int(user_input_str)

            if min_val is not None and user_input_int < min_val:
                print(f"Input must be at least {min_val}. Please try again.")
                continue
            if max_val is not None and user_input_int > max_val:
                print(f"Input must be no more than {max_val}. Please try again.")
                continue
            return user_input_int
        except ValueError:
            print("Invalid input. Please enter a whole number.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}. Please try again.")


def get_date_input(prompt: str) -> datetime.date:
    """
    Gets a date input from the user in 'YYYY-MM-DD' format.

    Args:
        prompt: The message to display to the user.

    Returns:
        A datetime.date object representing the entered date.
        Loops until a valid date in the specified format is provided.
    """
    while True:
        date_str = input(prompt + " (YYYY-MM-DD): ").strip()
        try:
            return datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            print("Invalid date format. Please use YYYY-MM-DD.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}. Please try again.")

def get_filepath_input(
    prompt: str,
    check_exists: bool = False,
    ensure_parent_dir_exists: bool = False,
    is_for_output: bool = False
) -> str:
    """
    Gets a filepath input from the user.

    Args:
        prompt: The message to display to the user.
        check_exists: If True, ensures the path exists and is a file.
                      Used for input files.
        ensure_parent_dir_exists: If True, ensures the parent directory of the
                                  given path exists. Useful for output files.
        is_for_output: If True, and the file exists, prompts for overwrite confirmation.


    Returns:
        The validated filepath string.
        Loops until a valid filepath (according to criteria) is provided.
    """
    while True:
        filepath = input(prompt).strip()
        if not filepath:
            print("Filepath cannot be empty. Please try again.")
            continue

        parent_dir = os.path.dirname(filepath)
        if not parent_dir: # If filepath is just a filename for current dir
            parent_dir = "." # os.path.dirname("") is "", we need "."

        if ensure_parent_dir_exists:
            if not os.path.isdir(parent_dir):
                print(f"Error: The parent directory '{parent_dir}' does not exist. Please create it or choose a different path.")
                continue

        if check_exists: # Typically for input files
            if not os.path.exists(filepath):
                print(f"Error: File not found at '{filepath}'. Please try again.")
                continue
            if not os.path.isfile(filepath):
                print(f"Error: Path '{filepath}' is not a file. Please try again.")
                continue

        if is_for_output and os.path.exists(filepath):
            overwrite_prompt = f"File '{filepath}' already exists. Overwrite? (yes/no): "
            while True:
                confirm = input(overwrite_prompt).strip().lower()
                if confirm == 'yes':
                    break
                elif confirm == 'no':
                    print("File will not be overwritten. Please enter a different filepath.")
                    # This will cause the outer loop to ask for filepath again
                    filepath = "" # Clear filepath to re-trigger outer loop's "empty" check if desired
                                  # or better, just continue the outer loop directly.
                    break 
                else:
                    print("Invalid input. Please enter 'yes' or 'no'.")
            if confirm == 'no': # If user chose not to overwrite, ask for path again
                continue 

        return filepath
    # (Your existing imports, core functions, and UI helper functions should be above this point)

# --- Main Application Logic ---

def run_otp_system() -> None:
    """
    Runs the main loop for the OTP Encryption System terminal application.
    """
    # This variable will hold the currently loaded OTP dictionary.
    # It's managed within this function's scope.
    loaded_otp_dictionary: Optional[Dict[str, bytes]] = None

    # --- Handler Functions for Menu Options ---
    # These are defined inside run_otp_system to have access to loaded_otp_dictionary
    # ------------------------------------------------------------------
# (Inside the run_otp_system function)
    def handle_generate_and_save_keys() -> None:
        nonlocal loaded_otp_dictionary # To modify the outer scope variable
        print("\n--- Generate and Save New OTP Key Dictionary ---")
        try:
            start_date = get_date_input("Enter start date for keys")
            num_years = get_int_input("Enter number of years to generate keys for: ", min_val=1)
            bytes_per_key = get_int_input(
                "Enter number of bytes per daily key (e.g., 10240 for 10KB): ",
                min_val=128 # A sensible minimum
            )

            print("The OTP dictionary will be encrypted. Choose a strong password.")
            while True:
                password = get_password_input("Enter password to encrypt dictionary: ")
                confirm_password = get_password_input("Confirm password: ")
                if password == confirm_password:
                    break
                else:
                    print("Passwords do not match. Please try again.")

            # NEW: Use the GUI dialog to get the output filepath
            output_filepath = get_filepath_from_dialog(
                dialog_mode="save",
                title="Save Encrypted OTP Dictionary As",
                filetypes=[("Encrypted OTP Files", "*.enc"), ("All files", "*.*")],
                defaultextension=".enc"
            )

            if not output_filepath: # User cancelled the dialog
                print("Operation cancelled by user (file not saved).")
                return

            print(f"\nGenerating OTP keys from {start_date.isoformat()} for {num_years} year(s)...")
            otp_dict_generated = generate_otp_key_dictionary(start_date, num_years, bytes_per_key)
            print(f"Generated {len(otp_dict_generated)} daily keys.")

            print(f"Saving and encrypting OTP dictionary to '{output_filepath}'...")
            save_otp_dictionary(otp_dict_generated, output_filepath, password)
            print("OTP Key Dictionary generated, encrypted, and saved successfully.")

            # Optionally, load the newly generated dictionary into memory
            loaded_otp_dictionary = otp_dict_generated
            print("Newly generated dictionary is now loaded and ready for use.")

        except (ValueError, IOError, OverflowError, Exception) as e:
            print(f"Error during key generation/saving: {e}")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")


    # -----------------------------------------------------
    def handle_load_keys() -> None:
        nonlocal loaded_otp_dictionary
        print("\n--- Load OTP Key Dictionary from File ---")
        try:
            # Use the new GUI function to get the filepath
            filepath = get_filepath_from_dialog(
                dialog_mode="open",
                title="Load Encrypted OTP Dictionary",
                filetypes=[("Encrypted OTP Files", "*.enc"), ("All files", "*.*")],
                # You could specify an initialdir if desired, e.g., initialdir=os.getcwd()
            )

            if not filepath:  # User cancelled the dialog or an error occurred
                print("File selection cancelled or failed. Aborting load operation.")
                return

            # The rest of the function remains largely the same
            password = get_password_input("Enter password to decrypt dictionary: ")

            print(f"Loading and decrypting OTP dictionary from '{filepath}'...")
            # Explicitly type the variable that will receive the loaded dictionary
            temp_loaded_dict: Dict[str, bytes] = load_otp_dictionary(filepath, password)
            loaded_otp_dictionary = temp_loaded_dict
            print(f"OTP Key Dictionary loaded successfully. {len(loaded_otp_dictionary)} keys available.")

        except (FileNotFoundError, PermissionError, InvalidTag, json.JSONDecodeError, TypeError, ValueError, IOError) as e: #
            print(f"Error loading OTP dictionary: {e}")
        except Exception as e: #
            print(f"An unexpected error occurred during loading: {e}")
        except KeyboardInterrupt: #
            print("\nOperation cancelled by user.")

    # --------------------------------------------------------------------
# (Inside the run_otp_system function)
    def handle_encrypt_message() -> None:
        if loaded_otp_dictionary is None:
            print("\nError: No OTP dictionary loaded. Please load a dictionary first (Option 2).")
            return

        print("\n--- Encrypt Message from File ---")
        try:
            # Get the input plaintext file
            plaintext_filepath = get_filepath_from_dialog(
                dialog_mode="open",
                title="Select Plaintext File to Encrypt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if not plaintext_filepath:
                print("File selection cancelled. Encryption aborted.")
                return

            # Get the output ciphertext file
            ciphertext_filepath = get_filepath_from_dialog(
                dialog_mode="save",
                title="Save Encrypted File As",
                filetypes=[("Data files", "*.dat"), ("All files", "*.*")],
                defaultextension=".dat"
            )
            if not ciphertext_filepath:
                print("File selection cancelled. Encryption aborted.")
                return

            date_obj = get_date_input("Enter date for the encryption key")
            date_iso = date_obj.isoformat()

            if date_iso not in loaded_otp_dictionary:
                print(f"Error: No key found in the loaded dictionary for the date {date_iso}.")
                return

            max_key_len = len(loaded_otp_dictionary[date_iso])
            position = get_int_input(
                f"Enter starting byte position for the key on {date_iso} (0 to {max_key_len - 1}): ",
                min_val=0,
                max_val=max_key_len - 1
            )

            print(f"Encrypting '{plaintext_filepath}' to '{ciphertext_filepath}' using key for {date_iso} at position {position}...")
            message_length = encrypt_message_from_file(
                plaintext_filepath,
                ciphertext_filepath,
                loaded_otp_dictionary,
                date_iso,
                position
            )
            print(f"Message encrypted successfully. {message_length} bytes processed.")
            print(f"IMPORTANT: The next available position for date {date_iso} is {position + message_length}.")
            print(f"Ciphertext saved to: {ciphertext_filepath}")

        except (FileNotFoundError, PermissionError, KeyError, ValueError, UnicodeDecodeError, IOError) as e:
            print(f"Error during encryption: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during encryption: {e}")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
    # -----------------------------------------------
# (Inside the run_otp_system function)
    def handle_decrypt_message() -> None:
        if loaded_otp_dictionary is None:
            print("\nError: No OTP dictionary loaded. Please load a dictionary first (Option 2).")
            return

        print("\n--- Decrypt Message to File ---")
        try:
            # Get the input ciphertext file
            ciphertext_filepath = get_filepath_from_dialog(
                dialog_mode="open",
                title="Select Ciphertext File to Decrypt",
                filetypes=[("Data files", "*.dat"), ("All files", "*.*")]
            )
            if not ciphertext_filepath:
                print("File selection cancelled. Decryption aborted.")
                return

            # Get the output plaintext file
            plaintext_filepath = get_filepath_from_dialog(
                dialog_mode="save",
                title="Save Decrypted Plaintext As",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                defaultextension=".txt"
            )
            if not plaintext_filepath:
                print("File selection cancelled. Decryption aborted.")
                return

            date_obj = get_date_input("Enter date for the decryption key")
            date_iso = date_obj.isoformat()

            if date_iso not in loaded_otp_dictionary:
                print(f"Error: No key found in the loaded dictionary for the date {date_iso}.")
                return

            max_key_len = len(loaded_otp_dictionary[date_iso])
            position = get_int_input(
                f"Enter starting byte position for the key on {date_iso} (0 to {max_key_len-1}): ",
                min_val=0,
                max_val=max_key_len - 1
            )

            print(f"Decrypting '{ciphertext_filepath}' to '{plaintext_filepath}' using key for {date_iso} at position {position}...")
            message_length = decrypt_message_to_file(
                ciphertext_filepath,
                plaintext_filepath,
                loaded_otp_dictionary,
                date_iso,
                position
            )
            print(f"Message decrypted successfully. {message_length} bytes processed.")
            print(f"Plaintext saved to: {plaintext_filepath}")

        except (FileNotFoundError, PermissionError, KeyError, ValueError, UnicodeDecodeError, IOError) as e:
            print(f"Error during decryption: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during decryption: {e}")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")

    # --------------------------------------------

    # --- Main Menu Loop ---
    while True:
        display_menu()
        choice = get_string_input("Enter your choice (1-5): ").strip()

        # Optional: Clear screen after getting choice for a cleaner interface
        # if os.name == 'nt': # For Windows
        #     os.system('cls')
        # else: # For macOS and Linux
        #     os.system('clear')

        if choice == '1':
            handle_generate_and_save_keys()
        elif choice == '2':
            handle_load_keys()
        elif choice == '3':
            handle_encrypt_message()
        elif choice == '4':
            handle_decrypt_message()
        elif choice == '5':
            print("Exiting OTP Encryption System. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

        if choice != '5': # Don't ask to continue if user is exiting
            press_enter_to_continue()


if __name__ == "__main__":
    # Ensure all function definitions (core logic, UI helpers) are complete before this call
    print("Welcome to the OTP Encryption System!")
    # It's good practice to wrap the main call in a try-except too, for any unhandled startup issues
    try:
        run_otp_system()
    except KeyboardInterrupt:
        print("\nApplication shut down by user. Goodbye!")
    except Exception as e:
        print(f"A critical unhandled error occurred: {e}")
        print("Application will now exit.")
