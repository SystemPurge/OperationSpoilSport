# SecureOTP-Manager

**SecureOTP-Manager** is a Python utility for managing time-based cryptographic keys. It implements a symmetric encryption workflow using the One-Time Pad (OTP) concept, backed by AES-256-GCM for secure key storage.

This project is intended for educational purposes and for users requiring a minimal, audit-friendly implementation of XOR-based encryption.

> **Note:** The instructions below assume a standard Linux environment.

## Technical Specifications

The application functionality is divided into three layers:

1.  **Key Generation**:
    * Utilizes `secrets.token_bytes` to generate high-entropy random byte streams.
    * Maps byte streams to specific ISO-8601 dates.
2.  **Key Storage (The Vault)**:
    * Keys are serialized to JSON and encrypted using **AES-256-GCM**.
    * **KDF**: PBKDF2-HMAC-SHA256 (200,000 iterations) is used to derive the storage key from a user-supplied password.
3.  **Operation**:
    * Performs bitwise XOR operations between plaintext bytes and the retrieved key stream.
    * Enforces date-specific key retrieval.

## Prerequisites

* Python 3.7+
* Linux Operating System

## Installation & Setup

It is highly recommended to run this tool within a Python virtual environment to manage dependencies securely and cleanly.

### 1. Clone the Repository

Open your terminal and download the source code:

    git clone https://github.com/SystemPurge/OperationSpoilSport.git
    cd OperationSpoilSport

### 2. Create a Virtual Environment

Create an isolated environment named `venv` in the project directory:

    python3 -m venv venv

### 3. Activate the Environment

Activate the environment to ensure you are using the isolated Python instance. Your terminal prompt should change to indicate `(venv)`.

    source venv/bin/activate

### 4. Install Dependencies

Install the required `cryptography` library inside the virtual environment:

    pip install cryptography

## Usage

Ensure your virtual environment is active (step 3 above), then run the application:

    python3 otp_manager.py

### Workflow

1.  **Configuration**: Upon first run, use **Option 1** to set your working directory. This directory will house your encrypted key files (`.enc`) and input/output text files.
2.  **Generate Keyfile**: Use **Option 2** to initialize a new key store. You will specify a start date, duration (years), and key size (bytes per day).
3.  **Load Keyfile**: Use **Option 3** to load an existing `.enc` file into memory.
4.  **Encrypt Data**:
    * Create a file named `message_input.txt` inside your configured working directory.
    * Paste the plaintext data you wish to encrypt into this file and save it.
    * Select **Encrypt** from the menu.
    * Provide the target Date and Byte Offset.
    * Output is written to `encrypted_message.txt`.
5.  **Decrypt Data**:
    * Ensure `encrypted_message.txt` exists in your working directory.
    * Select **Decrypt** from the menu.
    * Provide the matching Date and Byte Offset used during encryption.
    * Output is written to `decrypted_message.txt`.

> **Important:** Successful decryption requires the exact **Date** and **Start Position (Offset)** used during encryption.

## Project Structure

* `otp_manager.py`: Core application logic.
* `otp_config.json`: Local configuration file (generated on first run).
* `message_input.txt`: Input buffer for encryption operations (user created).
* `encrypted_message.txt`: Binary output of encryption operations.
* `decrypted_message.txt`: Output of decryption operations.

## License

This project is licensed under the **GNU General Public License v3.0**. See the `LICENSE` file for details.

## Disclaimer

This software is provided "as is," without warranty of any kind. Users are responsible for ensuring their use of this software complies with local laws and regulations regarding cryptographic software.