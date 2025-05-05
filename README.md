# Blowfish Demo v0.5

**Author**: Nikolay Dachev <nikolay@dachev.info>

## Description

`blowfish_demo.py` is an educational Python script that illustrates the Blowfish block cipher step by step. It provides full visibility into the algorithm’s Feistel rounds, P-array, and S-box operations, with optional key scheduling support via `--key`.

## Purpose

- **Learning tool**: Ideal for students and developers who want to explore Blowfish internal workings.
- **Debugging**: Helps verify and validate custom Blowfish implementations.
- **Detailed logging**: Generates comprehensive logs of both encryption and decryption processes.

## Requirements

- Python 3.6 or newer

## Installation

Clone the repository or download the script directly:

```bash
git clone https://github.com/yourusername/bf-analyzer.git
cd bf-analyzer
```

No additional libraries are needed—both the P-array and S-box tables are embedded directly in `blowfish_demo.py`.

## Usage

```bash
python blowfish_demo.py --input <text> --key <key_text> --logfile <log_basename> [--format dec|hex|both]
```

### Arguments

- `--input`  : Up to 8 ASCII characters to encrypt.
- `--key`    : Key as readable text (1–56 bytes) used for P/S initialization.
- `--logfile`: Base name for log files (creates `<logfile>_encrypt_<timestamp>.log` and `<logfile>_decrypt_<timestamp>.log`).
- `--format`: (default `dec`) Numeric format for logs:
  - `dec`  – decimal only
  - `hex`  – hexadecimal only
  - `both` – both decimal and hexadecimal

### Examples

```bash
# Default decimal logs with key
python blowfish_demo.py --input "BlowFish" --key "MySecret" --logfile demo

# Both formats
python blowfish_demo.py --input "test1234" --key "MySecretKey" --logfile debug --format both
```

## Log Structure

1. **Input Data**: plaintext, key text, and initial (L, R) blocks.
2. **Encryption**:
   - Initial values of L and R
   - Each round:
     - `L ^= P[i]`
     - `R ^= F(L)` with detailed F steps
     - Snapshot of first 16 entries from each S-box
   - Final `R ^= P[16]`, `L ^= P[17]`
3. **Encrypted Output**: encrypted block and resulting text.
4. **Decryption**: same steps in reverse order of P-array indices.

## Key Schedule Logs

When you run the script with `--key <key_text>`, a separate Key Schedule log file is generated named `<logfile>_keyschedule_<timestamp>.log`. This log includes:

- **Original P-array** printed in rows of six values, respecting your `--format` choice (decimal, hexadecimal, or both).
- **Key bytes** used for initialization.
- **Each P-array update**: shows the old value, the key-derived word, and the new value.
- **Each S-box update** (all 512 entries): shows the old and new values for each pair of entries, formatted per `--format`.

## How Blowfish Works

- 16-round Feistel network
- **P-array**: 18 subkeys (32-bit each)
- **S-boxes**: Four 256-entry tables
- **F-function**: `(S0[a] + S1[b]) XOR S2[c] + S3[d]` modulo 2³²

## Windows Executable

A stand-alone Windows executable is included in the `dist` folder of this repository (`dist\blowfish_demo.exe`). You can run it on Windows without installing Python:

```bat
> dist\blowfish_demo.exe -i "Hello123" -k "MySecret" -l demo -f both
```

## Future Enhancements

- Support cipher modes (CBC, CTR)
- Add padding for messages longer than 8 bytes
- Key scheduling from user-provided key

## License

MIT License – free to use, modify, and distribute.
