#!/usr/bin/env python3
# blowfish_demo.py
# Copyright (c) 2025 Nikolay Dachev <nikolay@dachev.info>
# Licensed under the MIT License.

import struct
import argparse
import time
import base64
from blowfish_tables import P as P_orig, S as S_orig

__version__ = "0.6"
BS = 8  # block size in bytes

def format_val(v, fmt):
    if fmt == "dec":
        return str(v)
    if fmt == "hex":
        return f"{v:#010x}"
    return f"{v} ({v:#010x})"

# ─── PKCS#7 padding ─────────────────────────────────────────────────
def pkcs7_pad(data: bytes) -> bytes:
    pad = BS - (len(data) % BS)
    return data + bytes([pad]) * pad

def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > BS:
        raise ValueError("Invalid padding")
    return data[:-pad]

# ─── F-function ───────────────────────────────────────────────────
def F(x, logger, fmt='dec', P=None, S=None):
    P = P or P_orig
    S = S or S_orig
    a = (x >> 24) & 0xFF
    b = (x >> 16) & 0xFF
    c = (x >> 8 ) & 0xFF
    d = x & 0xFF

    s0 = S[0][a]; s1 = S[1][b]; s2 = S[2][c]; s3 = S[3][d]
    sum_s = (s0 + s1) & 0xFFFFFFFF
    xor_s = (sum_s ^ s2) & 0xFFFFFFFF
    result = (xor_s + s3) & 0xFFFFFFFF

    if logger is not None:
        logger.append(f"bytes: a={a}, b={b}, c={c}, d={d}")
        logger.append("S lookups:")
        if fmt in ('dec','both'):
            logger.append(f"  S0[a]={s0}, S1[b]={s1}, S2[c]={s2}, S3[d]={s3}")
            logger.append(f"step1: {s0} + {s1} = {sum_s}")
            logger.append(f"step2: {sum_s} ^ {s2} = {xor_s}")
            logger.append(f"step3: {xor_s} + {s3} = {result}")
        if fmt in ('hex','both'):
            logger.append(f"  S0[a]={s0:#010x}, S1[b]={s1:#010x}, S2[c]={s2:#010x}, S3[d]={s3:#010x}")
            logger.append(f"step1: {s0:#010x} + {s1:#010x} = {sum_s:#010x}")
            logger.append(f"step2: {sum_s:#010x} ^ {s2:#010x} = {xor_s:#010x}")
            logger.append(f"step3: {xor_s:#010x} + {s3:#010x} = {result:#010x}")
    return result

def dump_sboxes(round_num, logger, fmt='dec', S=None):
    # S-box snapshots are disabled in this demo
    return

# ─── Encrypt one 64-bit block ────────────────────────────────────────
def encrypt_block(L, R, logger, fmt='dec', P=None, S=None):
    P = P or P_orig
    S = S or S_orig
    L &= 0xFFFFFFFF; R &= 0xFFFFFFFF
    if logger is not None:
        logger.append("=== Encryption ===")
        logger.append(f"Initial L={L}, R={R}")
    for i in range(16):
        if logger is not None:
            logger.append(f"\n-- Round {i+1} --")
        L = (L ^ P[i]) & 0xFFFFFFFF
        if logger is not None:
            logger.append(f"L after XOR P[{i}] = {L} ({L:#010x})")
        f_out = F(L, logger, fmt, P, S)
        R = (R ^ f_out) & 0xFFFFFFFF
        if logger is not None:
            logger.append(f"R after XOR F = {R} ({R:#010x})")
        L, R = R, L
    L, R = R, L
    R = (R ^ P[16]) & 0xFFFFFFFF
    L = (L ^ P[17]) & 0xFFFFFFFF
    if logger is not None:
        logger.append(f"\nFinal L={L}, R={R}")
    return L, R

# ─── Decrypt one 64-bit block ────────────────────────────────────────
def decrypt_block(L, R, logger, fmt='dec', P=None, S=None):
    P = P or P_orig
    S = S or S_orig
    L &= 0xFFFFFFFF; R &= 0xFFFFFFFF
    if logger is not None:
        logger.append("=== Decryption ===")
        logger.append(f"Initial L={L}, R={R}")
    for idx, i in enumerate(range(17, 1, -1), start=1):
        if logger is not None:
            logger.append(f"\n-- Round {idx} --")
        L = (L ^ P[i]) & 0xFFFFFFFF
        if logger is not None:
            logger.append(f"L after XOR P[{i}] = {L} ({L:#010x})")
        f_out = F(L, logger, fmt, P, S)
        R = (R ^ f_out) & 0xFFFFFFFF
        if logger is not None:
            logger.append(f"R after XOR F = {R} ({R:#010x})")
        L, R = R, L
    L, R = R, L
    R = (R ^ P[1]) & 0xFFFFFFFF
    L = (L ^ P[0]) & 0xFFFFFFFF
    if logger is not None:
        logger.append(f"\nFinal L={L}, R={R}")
    return L, R

# ─── Key Schedule ────────────────────────────────────────────────────
def key_schedule(key_bytes, fmt="dec", logger=None):
    P = P_orig.copy()
    S = [box.copy() for box in S_orig]
    if logger is not None:
        logger.append("=== Key Schedule ===")
    j = 0
    for i in range(18):
        word = 0
        for _ in range(4):
            word = (word << 8) | key_bytes[j]
            j = (j + 1) % len(key_bytes)
        old = P[i]
        P[i] ^= word & 0xFFFFFFFF
        if logger is not None:
            logger.append(f"P[{i}] = {format_val(old, fmt)} XOR {format_val(word, fmt)} → {format_val(P[i], fmt)}")
    L = R = 0
    for i in range(0, 18, 2):
        L, R = encrypt_block(L, R, None, fmt, P, S)
        P[i], P[i+1] = L, R
    for box in range(4):
        for idx in range(0, 256, 2):
            old0, old1 = S[box][idx], S[box][idx+1]
            L, R = encrypt_block(L, R, None, fmt, P, S)
            S[box][idx], S[box][idx+1] = L, R
            if logger is not None:
                logger.append(f"S[{box}][{idx}]   : {format_val(old0, fmt)} → {format_val(L, fmt)}")
                logger.append(f"S[{box}][{idx+1}]: {format_val(old1, fmt)} → {format_val(R, fmt)}")
    if logger is not None:
        logger.append("=== Key Schedule Complete ===\n")
    return P, S

# ─── Main ────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Blowfish demo with key & UTF-8 support",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-i", "--input", required=True, help="Plaintext (UTF-8)")
    parser.add_argument("-k", "--key", required=True, help="Key text (1–56 bytes)")
    parser.add_argument("-l", "--logfile", required=True, help="Log basename")
    parser.add_argument("-f", "--format", choices=["hex", "dec", "both"], default="dec", help="Numeric format")
    args = parser.parse_args()

    key_bytes = args.key.encode('utf-8')
    if not (1 <= len(key_bytes) <= 56):
        raise SystemExit("Error: key length must be 1–56 bytes")

    ts = time.strftime("%Y%m%d_%H%M%S")

    # 1) Key schedule logging
    ks_log = []
    P, S = key_schedule(key_bytes, args.format, ks_log)
    ks_file = f"{args.logfile}_keyschedule_{ts}.log"
    with open(ks_file, "w", encoding="utf-8") as f:
        f.write("\n".join(ks_log))

    # 2) Pad & encrypt all blocks
    data = args.input.encode('utf-8')
    padded = pkcs7_pad(data)
    enc_log = ["=== ENCRYPTION DETAILS ==="]
    ciphertext = bytearray()
    for i in range(0, len(padded), BS):
        block = padded[i:i+BS]
        L, R = struct.unpack(">II", block)
        L2, R2 = encrypt_block(L, R, enc_log, args.format, P, S)
        ciphertext += struct.pack(">II", L2, R2)
    ct_b64 = base64.b64encode(ciphertext).decode('ascii')
    enc_file = f"{args.logfile}_encrypt_{ts}.log"
    with open(enc_file, "w", encoding="utf-8") as f:
        f.write(f"Ciphertext (Base64):\n{ct_b64}\n\n")
        f.write("\n".join(enc_log))

    # 3) Decrypt & unpad all blocks
    dec_log = ["=== DECRYPTION DETAILS ==="]
    ct_bytes = base64.b64decode(ct_b64)
    decrypted = bytearray()
    for i in range(0, len(ct_bytes), BS):
        block = ct_bytes[i:i+BS]
        L, R = struct.unpack(">II", block)
        L2, R2 = decrypt_block(L, R, dec_log, args.format, P, S)
        decrypted += struct.pack(">II", L2, R2)
    plaintext = pkcs7_unpad(decrypted).decode('utf-8')
    dec_file = f"{args.logfile}_decrypt_{ts}.log"
    with open(dec_file, "w", encoding="utf-8") as f:
        f.write(f"Recovered plaintext:\n{plaintext}\n\n")
        f.write("\n".join(dec_log))

    assert plaintext == args.input, "Decryption failed—mismatch!"

    print(f"Key schedule log: {ks_file}")
    print(f"Encryption log:    {enc_file}")
    print(f"Decryption log:    {dec_file}")
    print(f"Ciphertext (Base64): {ct_b64}")
    print(f"Recovered plaintext: {plaintext}")

if __name__ == "__main__":
    main()
