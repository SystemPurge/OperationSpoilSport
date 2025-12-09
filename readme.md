# OperationSpoilSport (OTP Manager)

A robust Python-based implementation of a One-Time Pad (OTP) encryption system. This tool manages the generation, secure storage, and utilization of OTP keys to provide unbreakable encryption for messages, provided the fundamental rules of OTP are followed.

## Overview

The application functions as a CLI (Command Line Interface) tool with GUI file dialogs for ease of use. It allows the user to generate a "pad" of cryptographically secure random bytes assigned to specific dates, ensuring that a unique key segment is available for every day of operation.

## Key Features

### 1. True OTP Encryption
* **Mechanism:** Implements pure XOR encryption using `secrets` (cryptographically secure random number generator).
* **Security:** Theoretically unbreakable (Information Theoretic Security) when the key is random, as large as the message, and never reused.

### 2. Secure Key Database
* **Storage:** The generated OTP keys (the "pad") are stored in a dictionary mapping dates (`YYYY-MM-DD`) to byte arrays.
* **Protection:** The key database file is encrypted at rest using **AES-256-GCM**.
* **Derivation:** The encryption key for the database is derived from a user password using **PBKDF2-HMAC-SHA256** with high iteration counts and a random salt.

### 3. Granular Message Handling
* **Date-Based:** Encryption keys are selected based on the date of the message.
* **Offset Management:** Supports starting encryption at specific byte positions within a daily key. This allows multiple messages to be sent on the same day without reusing the same key segment (a critical security requirement).

### 4. Usability
* **Hybrid Interface:** Combines a text-based menu for options with native OS file dialogs (Tkinter) for selecting input and output files.
* **Validation:** Includes checks for key exhaustion, date validity, and file integrity.

## Requirements

* **Python:** 3.12+
* **System Dependencies:** Tkinter (usually `python3-tk` or `python3-tkinter` on Linux).
* **Python Libraries:**
    * `cryptography`

## Usage

1.  **Install Dependencies:**
    ```bash
    pip install cryptography
    ```
2.  **Run the System:**
    ```bash
    python3 otp_manager.py
    ```
3.  **Workflow:**
    * **Generate Keys:** Create a new encrypted database file covering a specific date range (e.g., 1 year).
    * **Load Keys:** Unlock your database with your password.
    * **Encrypt:** Select a plaintext file, a date, and a start position. The system outputs the ciphertext.
    * **Decrypt:** Select a ciphertext file, the corresponding date, and start position to retrieve the original message.
