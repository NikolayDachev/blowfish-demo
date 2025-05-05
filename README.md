# Blowfish Demo v0.6

**Author**: Nikolay Dachev <nikolay@dachev.info>

## Description

`blowfish_demo.py` is an educational Python script that illustrates the Blowfish block cipher step by step. It provides full visibility into the algorithm’s Feistel rounds, P-array, and S-box operations, with optional key scheduling support via `--key`.

## Purpose

- **Learning tool**: Ideal for students and developers who want to explore Blowfish internal workings.
- **Debugging**: Helps verify and validate custom Blowfish implementations.
- **Detailed logging**: Generates comprehensive logs of encryption, decryption, and key schedule processes.

## Requirements

- Python 3.6 or newer

## Installation

Clone the repository or download the script directly:

```bash
git clone https://github.com/NikolayDachev/blowfish-demo.git
cd blowfish-demo
```

No additional libraries are needed—both the P-array and S-box tables are embedded directly in `blowfish_demo.py`.

## Usage

```bash
python blowfish_demo.py --input <text> --key <key_text> --logfile <log_basename> [--format dec|hex|both]
```

### Arguments

- `--input`   : Any UTF-8 text to encrypt (will be padded to 8-byte blocks via PKCS#7).
- `--key`     : Key as readable text (1–56 bytes) used for P/S initialization.
- `--logfile` : Base name for log files; generates:
  - `<logfile>_keyschedule_<timestamp>.log`
  - `<logfile>_encrypt_<timestamp>.log`
  - `<logfile>_decrypt_<timestamp>.log`
- `--format`  : (default `dec`) Numeric format for logs:
  - `dec`  – decimal only
  - `hex`  – hexadecimal only
  - `both` – both decimal and hexadecimal

### Examples

```bash
# Default decimal logs with key
python blowfish_demo.py --input "BlowFish" --key "MySecret" --logfile demo

# Both formats and Unicode input
python blowfish_demo.py --input "тест123 😀" --key "MySecretKey" --logfile debug --format both
```

## Log Structure

1. **Key Schedule** (`*_keyschedule_*.log`):
   - Original P-array in rows of six values.
   - Key bytes used for XOR mixing.
   - Each P-array update showing old, key-word, and new values.
   - Each S-box update (512 entries) showing pairs old→new.
2. **Encryption** (`*_encrypt_*.log`):
   - Padded plaintext blocks and their indices.
   - For each 8-byte block:
     - Raw block bytes (hex).
     - Detailed Feistel rounds:
       - `L ^= P[i]`
       - `R ^= F(L)` with **step1** (`S0+S1`), **step2** (XOR), **step3** (addition) breakdown in dec/hex.
       - Swap and final P-array XOR.
   - **Ciphertext** printed in Base64 and logged.
3. **Decryption** (`*_decrypt_*.log`):
   - Mirrors encryption in reverse order:
     - Base64 → bytes → per-block decryption logs → PKCS#7 unpadding.
   - Recovered plaintext identical to original UTF-8 input.

## Padding & Output Details

- **PKCS#7 padding** ensures the UTF-8 input is extended to a multiple of 8 bytes by appending N bytes of value N (1 ≤ N ≤ 8). Upon decryption, these padding bytes are automatically removed to restore the original data.
- **Console Output**: After the script completes, it prints informational lines naming the three log files, the Base64 ciphertext, and the recovered plaintext.

## How Blowfish Works

- 16-round Feistel network
- **P-array**: 18 subkeys (32-bit each)
- **S-boxes**: Four 256-entry tables
- **F-function**: `(S0[a] + S1[b]) XOR S2[c] + S3[d]` modulo 2³²

## Windows Executable build

```bat
pyinstaller --onefile --console blowfish_demo.py
```

## Windows Executable usage

A stand-alone Windows executable (`dist\blowfish_demo.exe`) is included in this repo. Run without Python:

```bat
> dist\blowfish_demo.exe -i "Hello123" -k "MySecret" -l demo -f both
```

## License

MIT License – free to use, modify, and distribute.
