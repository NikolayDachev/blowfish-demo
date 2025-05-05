#!/usr/bin/env python3

# blowfish_manual.py
# Copyright (c) 2025 Nikolay Dachev <nikolay@dachev.info>
# Licensed under the MIT License.

import struct
import argparse
import time
from blowfish_tables import P, S  # P: list of 18 uint32; S: list of 4×256 uint32

__version__ = "0.1"

# ─── F-function with detailed logging and 32-bit masking ─────────────
def F(x, logger, fmt='dec'):
    # Split 32-bit word into four bytes
    a = (x >> 24) & 0xFF
    b = (x >> 16) & 0xFF
    c = (x >> 8 ) & 0xFF
    d = x & 0xFF

    # S-box lookups
    s0 = S[0][a]
    s1 = S[1][b]
    s2 = S[2][c]
    s3 = S[3][d]

    # Detailed intermediate values
    sum_s  = (s0 + s1) & 0xFFFFFFFF
    xor_s  = (sum_s ^ s2) & 0xFFFFFFFF
    result = (xor_s + s3) & 0xFFFFFFFF

    # Log the breakdown
    logger.append(f"bytes: a={a}, b={b}, c={c}, d={d}")
    logger.append("S lookups:")
    if fmt in ('dec','both'):
        logger.append(f"  S0[a] = {s0}")
        logger.append(f"  S1[b] = {s1}")
        logger.append(f"  S2[c] = {s2}")
        logger.append(f"  S3[d] = {s3}")
    if fmt in ('hex','both'):
        logger.append(f"  S0[a] = {s0:#010x}")
        logger.append(f"  S1[b] = {s1:#010x}")
        logger.append(f"  S2[c] = {s2:#010x}")
        logger.append(f"  S3[d] = {s3:#010x}")

    # Log each step of F
    if fmt in ('dec','both'):
        logger.append(f"step1: S0[a] + S1[b] = {s0} + {s1} = {sum_s} (dec)")
        logger.append(f"step2: step1 XOR S2[c] = {sum_s} ^ {s2} = {xor_s} (dec)")
        logger.append(f"step3: step2 + S3[d] = {xor_s} + {s3} = {result} (dec)")
    if fmt in ('hex','both'):
        logger.append(f"step1: {s0:#010x} + {s1:#010x} = {sum_s:#010x} (hex)")
        logger.append(f"step2: {sum_s:#010x} ^ {s2:#010x} = {xor_s:#010x} (hex)")
        logger.append(f"step3: {xor_s:#010x} + {s3:#010x} = {result:#010x} (hex)")

    return result

# ─── Dump first 16 entries of each S-box in dec/hex/both ──────────────
def dump_sboxes(round_num, logger, fmt='dec'):
    logger.append(f"--- S-box snapshot after round {round_num} ---")
    for i in range(4):
        if fmt in ('dec','both'):
            dec_vals = ', '.join(str(v) for v in S[i][:16])
            logger.append(f"  S[{i}][0..15] (dec): {dec_vals}")
        if fmt in ('hex','both'):
            hex_vals = ', '.join(f"{v:#06x}" for v in S[i][:16])
            logger.append(f"  S[{i}][0..15] (hex): {hex_vals}")
    logger.append("")

# ─── Encrypt one 64-bit block (two 32-bit words) ─────────────────────
def encrypt_block(L, R, logger, fmt='dec'):
    # Mask to 32 bits
    L &= 0xFFFFFFFF
    R &= 0xFFFFFFFF

    logger.append("=== Encryption ===")
    logger.append(f"Initial L={L}, R={R}")

    for i in range(16):
        logger.append(f"-- Round {i+1} --")

        # L = L XOR P[i]
        L = (L ^ P[i]) & 0xFFFFFFFF
        logger.append(f"L after XOR P[{i}] = {L} ({L:#010x})")

        # F-function and R update
        f_out = F(L, logger, fmt)
        R = (R ^ f_out) & 0xFFFFFFFF
        logger.append(f"R after XOR F = {R} ({R:#010x})")

        # Dump part of the S-boxes
        dump_sboxes(i+1, logger, fmt)

        # Swap
        L, R = R, L

    # Final swap and two more P-array XORs
    L, R = R, L
    R = (R ^ P[16]) & 0xFFFFFFFF
    L = (L ^ P[17]) & 0xFFFFFFFF
    logger.append(f"Final L={L}, R={R}")

    return L, R

# ─── Decrypt one 64-bit block ─────────────────────────────────────────
def decrypt_block(L, R, logger, fmt='dec'):
    L &= 0xFFFFFFFF
    R &= 0xFFFFFFFF

    logger.append("=== Decryption ===")
    logger.append(f"Initial L={L}, R={R}")

    for round_idx, i in enumerate(range(17, 1, -1), start=1):
        logger.append(f"-- Round {round_idx} --")

        L = (L ^ P[i]) & 0xFFFFFFFF
        logger.append(f"L after XOR P[{i}] = {L} ({L:#010x})")

        f_out = F(L, logger, fmt)
        R = (R ^ f_out) & 0xFFFFFFFF
        logger.append(f"R after XOR F = {R} ({R:#010x})")

        L, R = R, L

    # Final swap and two more P-array XORs
    L, R = R, L
    R = (R ^ P[1]) & 0xFFFFFFFF
    L = (L ^ P[0]) & 0xFFFFFFFF
    logger.append(f"Final L={L}, R={R}")

    return L, R

# ─── Helpers to pack/unpack 8-byte blocks ─────────────────────────────
def str_to_block(text):
    data = text.encode('utf-8')
    data = data.ljust(8, b'\0')[:8]
    return struct.unpack(">II", data)

def block_to_str(L, R):
    return struct.pack(">II", L, R).rstrip(b'\0').decode('utf-8', errors='ignore')

# ─── Main entrypoint ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Blowfish demo with detailed logs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Input string (up to 8 ASCII chars)"
    )
    parser.add_argument(
        "-l", "--logfile",
        required=True,
        help="Base filename for logs"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["hex","dec","both"],
        default="dec",
        help="Numeric format for logged values"
    )
    args = parser.parse_args()

    ts = time.strftime("%Y%m%d_%H%M%S")
    enc_file = f"{args.logfile}_encrypt_{ts}.log"
    dec_file = f"{args.logfile}_decrypt_{ts}.log"

    # Convert input to two 32-bit halves
    L, R = str_to_block(args.input)

    # Encryption phase
    encrypt_log = [
        "=== INPUT DATA ===",
        f"Plaintext: {args.input}",
        f"Block (L,R): {L}, {R}",
        ""
    ]
    L_enc, R_enc = encrypt_block(L, R, encrypt_log, fmt=args.format)
    encrypted_text = block_to_str(L_enc, R_enc)
    encrypt_log += [
        "",
        "=== ENCRYPTION RESULT ===",
        f"Encrypted block: {L_enc}, {R_enc}",
        f"Encrypted text: {encrypted_text}"
    ]
    with open(enc_file, "w") as f:
        f.write("\n".join(encrypt_log))

    # Decryption phase
    decrypt_log = [
        "=== INPUT DATA ===",
        f"Encrypted block: {L_enc}, {R_enc}",
        ""
    ]
    L_dec, R_dec = decrypt_block(L_enc, R_enc, decrypt_log, fmt=args.format)
    decrypted_text = block_to_str(L_dec, R_dec)
    decrypt_log += [
        "",
        "=== DECRYPTION RESULT ===",
        f"Decrypted block: {L_dec}, {R_dec}",
        f"Decrypted text: {decrypted_text}"
    ]
    with open(dec_file, "w") as f:
        f.write("\n".join(decrypt_log))

    print(f"Logs written to {enc_file} and {dec_file}")

if __name__ == "__main__":
    main()
