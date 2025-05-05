#!/usr/bin/env python3
# blowfish_demo.py
# Copyright (c) 2025 Nikolay Dachev <nikolay@dachev.info>
# Licensed under the MIT License.

import struct
import argparse
import time
from blowfish_tables import P as P_orig, S as S_orig  # original tables

__version__ = "0.5"

def format_val(v, fmt):
    """Format a 32-bit word according to fmt."""
    if fmt == "dec":
        return str(v)
    if fmt == "hex":
        return f"{v:#010x}"
    # both
    return f"{v} ({v:#010x})"

# ─── F-function ───────────────────────────────────────────────────
def F(x, logger, fmt='dec', P=None, S=None):
    """Blowfish F-function with detailed logging."""
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
    """No-op: S-box snapshots have been removed."""
    return

# ─── Encrypt one 64-bit block ────────────────────────────────────────
def encrypt_block(L, R, logger, fmt='dec', P=None, S=None):
    """Encrypt one 64-bit block."""
    P = P or P_orig
    S = S or S_orig
    L &= 0xFFFFFFFF; R &= 0xFFFFFFFF
    if logger is not None:
        logger.append("=== Encryption ===")
        logger.append(f"Initial L={L}, R={R}")
    for i in range(16):
        if logger: logger.append(f"\n-- Round {i+1} --")
        L = (L ^ P[i]) & 0xFFFFFFFF
        if logger: logger.append(f"L after XOR P[{i}] = {L} ({L:#010x})")
        f_out = F(L, logger, fmt, P, S)
        R = (R ^ f_out) & 0xFFFFFFFF
        if logger: logger.append(f"R after XOR F = {R} ({R:#010x})")
        # S-box snapshots removed
        L, R = R, L
    # Final swap and P-array XORs according to spec
    L, R = R, L
    R = (R ^ P[16]) & 0xFFFFFFFF   # P17
    L = (L ^ P[17]) & 0xFFFFFFFF   # P18
    if logger: logger.append(f"\nFinal L={L}, R={R}")
    return L, R

# ─── Decrypt one 64-bit block ────────────────────────────────────────
def decrypt_block(L, R, logger, fmt='dec', P=None, S=None):
    """Decrypt one 64-bit block."""
    P = P or P_orig
    S = S or S_orig
    L &= 0xFFFFFFFF; R &= 0xFFFFFFFF
    if logger is not None:
        logger.append("=== Decryption ===")
        logger.append(f"Initial L={L}, R={R}")
    for round_idx, i in enumerate(range(17, 1, -1), start=1):
        if logger: logger.append(f"\n-- Round {round_idx} --")
        L = (L ^ P[i]) & 0xFFFFFFFF
        if logger: logger.append(f"L after XOR P[{i}] = {L} ({L:#010x})")
        f_out = F(L, logger, fmt, P, S)
        R = (R ^ f_out) & 0xFFFFFFFF
        if logger: logger.append(f"R after XOR F = {R} ({R:#010x})")
        # S-box snapshots removed
        L, R = R, L
    # Final swap and P-array XORs in reverse order
    L, R = R, L
    R = (R ^ P[1]) & 0xFFFFFFFF    # P2
    L = (L ^ P[0]) & 0xFFFFFFFF    # P1
    if logger: logger.append(f"\nFinal L={L}, R={R}")
    return L, R

# ─── Key Schedule (after encrypt/decrypt definitions) ─────────────────
def key_schedule(key_bytes, fmt="dec", logger=None):
    """Mix the user key into P-array and S-boxes, logging each step."""
    P = P_orig.copy()
    S = [box.copy() for box in S_orig]
    if logger is not None:
        logger.append("=== Key Schedule ===")
        logger.append("Original P-array:")
        for i in range(0, len(P), 6):
            row = P[i:i+6]
            logger.append("  " + ", ".join(format_val(x, fmt) for x in row))
        logger.append(f"Key bytes: {list(key_bytes)}")
    # 1) XOR P-array
    key_len = len(key_bytes); j = 0
    for i in range(18):
        word = 0
        for _ in range(4):
            word = (word << 8) | key_bytes[j]
            j = (j + 1) % key_len
        old = P[i]
        P[i] ^= word
        if logger: logger.append(f"P[{i}] = {format_val(old, fmt)} XOR {format_val(word, fmt)} → {format_val(P[i], fmt)}")
    # 2) Re-encrypt zero block to reinitialize P and S
    L = R = 0
    for i in range(0, 18, 2):
        L, R = encrypt_block(L, R, None, fmt, P, S)
        P[i], P[i+1] = L, R
    for box in range(4):
        for idx in range(0, 256, 2):
            old0, old1 = S[box][idx], S[box][idx+1]
            L, R = encrypt_block(L, R, None, fmt, P, S)
            S[box][idx], S[box][idx+1] = L, R
            if logger:
                logger.append(f"S[{box}][{idx}]   : {format_val(old0, fmt)} → {format_val(L, fmt)}")
                logger.append(f"S[{box}][{idx+1}]: {format_val(old1, fmt)} → {format_val(R, fmt)}")
    if logger: logger.append("=== Key Schedule Complete ===\n")
    return P, S

# ─── Helpers ─────────────────────────────────────────────────────────
def str_to_block(text):
    data = text.encode('utf-8').ljust(8, b'\0')[:8]
    return struct.unpack(">II", data)

def block_to_str(L, R):
    return struct.pack(">II", L, R).rstrip(b'\0').decode('utf-8', errors='ignore')

# ─── Main entrypoint ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Blowfish demo with key support and detailed logs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-V","--version",action="version",version=f"%(prog)s {__version__}")
    parser.add_argument("-i","--input",  required=True,help="Input string (up to 8 ASCII chars)")
    parser.add_argument("-k","--key",    required=True,help="Key as readable text (1–56 bytes)")
    parser.add_argument("-l","--logfile",required=True,help="Base name for log files")
    parser.add_argument("-f","--format", choices=["hex","dec","both"],default="dec",help="Numeric format for logs")
    args = parser.parse_args()

    key_bytes = args.key.encode('utf-8')
    if not (1 <= len(key_bytes) <= 56):
        raise SystemExit("Error: key length must be between 1 and 56 bytes")

    ts = time.strftime("%Y%m%d_%H%M%S")

    # Key schedule log
    ks_log=[] 
    P,S = key_schedule(key_bytes, fmt=args.format, logger=ks_log)
    ks_file=f"{args.logfile}_keyschedule_{ts}.log"
    with open(ks_file,"w") as f: f.write("\n".join(ks_log))

    # Encryption log
    enc_log=["=== INPUT DATA ===",
             f"Plaintext: {args.input}",
             f"Key: {args.key}",
             f"Block (L,R): {str_to_block(args.input)}",""]
    L_enc,R_enc=encrypt_block(*str_to_block(args.input),enc_log,fmt=args.format,P=P,S=S)
    enc_text=block_to_str(L_enc,R_enc)
    enc_log+=["","=== ENCRYPTION RESULT ===",
              f"Encrypted block: {L_enc},{R_enc}",
              f"Encrypted text: {enc_text}"]
    enc_file=f"{args.logfile}_encrypt_{ts}.log"
    with open(enc_file,"w") as f: f.write("\n".join(enc_log))

    # Decryption log
    dec_log=["=== INPUT DATA ===",
             f"Encrypted block: {L_enc},{R_enc}",
             f"Key: {args.key}",""]
    L_dec,R_dec=decrypt_block(L_enc,R_enc,dec_log,fmt=args.format,P=P,S=S)
    dec_text=block_to_str(L_dec,R_dec)
    dec_log+=["","=== DECRYPTION RESULT ===",
              f"Decrypted block: {L_dec},{R_dec}",
              f"Decrypted text: {dec_text}"]
    dec_file=f"{args.logfile}_decrypt_{ts}.log"
    with open(dec_file,"w") as f: f.write("\n".join(dec_log))

    assert dec_text==args.input, "Decryption failed—incorrect key or tables!"

    print(f"Key schedule log: {ks_file}")
    print(f"Encryption log:    {enc_file}")
    print(f"Decryption log:    {dec_file}")

if __name__=="__main__":
    main()
