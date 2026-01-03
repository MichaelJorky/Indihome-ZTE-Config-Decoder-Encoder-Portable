#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZTE Universal Encoder (supports payload types 0..6)

Features:
 - Supports payload types 0..6:
   0 = plain (no encryption)
   1 = (treated as plain)
   2 = AES-128-ECB (direct key)
   3 = AES-256-CBC / AES-128-CBC derived from model (CBC)
   4 = AES-256-CBC / AES-128-CBC derived from serial/signature (CBC)
   5 = AES-CBC with provided key_prefix/iv_prefix behavior
   6 = ZTE New GPON style: template header (default 0x90 bytes) + AES-ECB payload
 - Compression: zlib (default), lzma, none
 - Key derivation helpers (serial+mac -> kp)
 - Supports reading header template for type-6 and updating payload size at configurable offset
 - Verification: decrypt new bin and compare decompressed bytes to input xml
"""

from __future__ import annotations
import argparse
import struct
import zlib
import lzma
import os
import sys
import hashlib
from typing import Optional, Tuple
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except Exception:
    raise SystemExit("pycryptodome is required. Install with: pip install pycryptodome")

# Try import zcu helpers if present (optional)
try:
    import zcu
    from zcu.xcryptors import Xcryptor, CBCXcryptor
    from zcu.known_keys import run_any_keygen
    ZCU_AVAILABLE = True
except Exception:
    ZCU_AVAILABLE = False

# Defaults
DEFAULT_IV_STR = "ZTE%FN$GponNJ025"
HEADER_LEN_DEFAULT = 0x90
SIZE_OFFSET_DEFAULT = 0x48  # where to write payload size (little-endian) for type-6 template

# ---------------- utilities ----------------
def read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def write_bytes(path: str, b: bytes):
    with open(path, "wb") as f:
        f.write(b)

def compress_bytes(data: bytes, method: str) -> bytes:
    if method == "none":
        return data
    if method == "zlib":
        return zlib.compress(data)
    if method == "lzma":
        return lzma.compress(data)
    raise ValueError("Unknown compression")

def decompress_bytes(data: bytes, method: str) -> bytes:
    if method == "none":
        return data
    if method == "zlib":
        return zlib.decompress(data)
    if method == "lzma":
        return lzma.decompress(data)
    raise ValueError("Unknown compression")

def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, 16))

def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), 16)

def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, 16))

def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), 16)

# ---------------- key derivation helpers ----------------
def normalize_mac_hex(mac: str) -> str:
    s = mac.strip().replace(":", "").lower()
    if len(s) != 12:
        raise ValueError("MAC must be 12 hex chars")
    return s

def derive_kp_from_serial_mac(serial: str, mac: str) -> str:
    mac_clean = normalize_mac_hex(mac)
    mac_bytes = bytes.fromhex(mac_clean)
    mac_rev_hex = ("%02x%02x%02x%02x%02x%02x" %
                   (mac_bytes[5], mac_bytes[4], mac_bytes[3], mac_bytes[2], mac_bytes[1], mac_bytes[0]))
    if len(serial) == 12:
        kp1 = serial[4:]
    elif len(serial) == 19:
        kp1 = serial[11:]
    else:
        raise ValueError("Serial length unexpected (expect 12 or 19)")
    return kp1 + mac_rev_hex

def key_from_kp_first16(kp: str) -> bytes:
    b = kp.encode("utf-8")
    if len(b) >= 16:
        return b[:16]
    return b + b'\x00' * (16 - len(b))

def key_from_kp_md5(kp: str) -> bytes:
    return hashlib.md5(kp.encode("utf-8")).digest()

# ---------------- header helper for type6 ----------------
def update_type6_header(header: bytearray, payload_len: int, size_offset: int, payload_type: int = 6) -> bytearray:
    """
    Update header template fields needed:
    - write payload length (LE) at size_offset
    - write payload type somewhere if required (optionally)
    Caller must ensure header is mutable bytearray of length >= size_offset+4
    """
    header[size_offset:size_offset+4] = struct.pack("<I", payload_len)
    # Optionally update a 'payload type' byte if header has it at a known offset.
    # Many firmware place payload type at 0x44 or similar. We avoid touching unknown fields by default.
    return header

# ---------------- main encoder ----------------
def encode(
    xml_path: str,
    out_path: str,
    payload_type: int,
    compression: str,
    key_bytes: Optional[bytes],
    iv_bytes: Optional[bytes],
    serial: Optional[str],
    mac: Optional[str],
    signature: Optional[str],
    template_path: Optional[str],
    header_len: int,
    size_offset: int,
    try_key_methods: bool,
    verbose: bool
) -> bool:
    # Read xml
    xml_b = read_bytes(xml_path)
    if verbose:
        print(f"[+] Read XML {xml_path} ({len(xml_b)} bytes)")
    # compress
    comp = compress_bytes(xml_b, compression)
    if verbose:
        print(f"[+] Compressed ({compression}) -> {len(comp)} bytes")

    # Determine key/iv if not provided for types that need it
    kp = None
    if payload_type in (4, 6) and (serial and mac):
        kp = derive_kp_from_serial_mac(serial, mac)
        if verbose:
            print(f"[+] Derived kp from serial+mac: {kp}")
    if payload_type in (3,4) and not key_bytes and ZCU_AVAILABLE:
        # try zcu keygen if available (best-effort)
        try:
            params = SimpleNamespace(signature=signature or "", serial=serial or "", mac=mac or "")
            kg = run_any_keygen(params, 'serial' if serial else 'signature')
            if kg:
                # run_any_keygen may return (key, iv, source)
                key_bytes = kg[0] if isinstance(kg, (list,tuple)) else kg
                if verbose:
                    print(f"[+] run_any_keygen gave key: {repr(key_bytes)}")
        except Exception:
            pass

    # candidate key strategies (try if requested)
    key_candidates = []
    if key_bytes:
        key_candidates.append(("given", key_bytes))
    if kp:
        key_candidates.append(("kp-first16", key_from_kp_first16(kp)))
        key_candidates.append(("kp-md5", key_from_kp_md5(kp)))
    if try_key_methods and key_bytes is None and kp is None:
        # no clues, try empty key
        key_candidates.append(("zeros-16", b"\x00" * 16))

    # Build payload bytes according to payload type
    encrypted_payload = None
    chosen_key_name = None
    chosen_key = None

    # For types that do not require encryption
    if payload_type in (0, 1):
        encrypted_payload = comp
        if verbose:
            print("[+] Payload type 0/1: no encryption")
    else:
        # Try candidate keys in order until verification ok (if we'll verify later)
        # We'll produce an encrypted payload per candidate and verify by decrypting it.
        if payload_type == 2:
            # AES-128-ECB with provided key (expects exact 16-byte key)
            if not key_candidates:
                raise ValueError("Type-2 requires --key")
            for name, kb in key_candidates:
                if verbose:
                    print(f"[=] Trying key candidate {name}: {kb.hex()}")
                try:
                    enc = aes_ecb_encrypt(comp, kb)
                    # quick decrypt-check
                    dec = aes_ecb_decrypt(enc, kb)
                    if dec == comp:
                        chosen_key_name, chosen_key = name, kb
                        encrypted_payload = enc
                        if verbose: print(f"[+] Key {name} works for ECB")
                        break
                except Exception:
                    continue
            if encrypted_payload is None:
                # fallback: use first candidate even if decrypt check failed
                chosen_key_name, chosen_key = key_candidates[0]
                encrypted_payload = aes_ecb_encrypt(comp, chosen_key)
        elif payload_type in (3, 4, 5):
            # AES-CBC variants
            if not key_candidates and not key_bytes:
                # try derive from kp if present
                if kp:
                    default_k = key_from_kp_first16(kp)
                    key_candidates.append(("kp-first16", default_k))
            if iv_bytes is None:
                # default IV
                iv_bytes = DEFAULT_IV_STR.encode("utf-8")
            for name, kb in key_candidates:
                if verbose:
                    print(f"[=] Trying CBC key candidate {name}: {kb.hex()} iv={iv_bytes!r}")
                try:
                    enc = aes_cbc_encrypt(comp, kb, iv_bytes)
                    # verify quickly
                    dec = aes_cbc_decrypt(enc, kb, iv_bytes)
                    if dec == comp:
                        chosen_key_name, chosen_key = name, kb
                        encrypted_payload = enc
                        if verbose: print(f"[+] CBC key {name} passed verify")
                        break
                except Exception:
                    continue
            if encrypted_payload is None:
                # fallback: pick first candidate or raise
                if key_candidates:
                    chosen_key_name, chosen_key = key_candidates[0]
                    encrypted_payload = aes_cbc_encrypt(comp, chosen_key, iv_bytes)
                else:
                    raise ValueError("No key for CBC encryption")
        elif payload_type == 6:
            # ZTE type-6: AES-ECB usually using kp-first16; MUST use header template
            if not template_path:
                raise ValueError("Type-6 requires --template (original config.bin) to copy header")
            if not kp and not key_candidates:
                raise ValueError("Type-6 requires serial+mac or explicit key")
            # build candidate if none
            if not key_candidates and kp:
                key_candidates.append(("kp-first16", key_from_kp_first16(kp)))
            iv_bytes = None  # not used for ECB
            for name, kb in key_candidates:
                if verbose:
                    print(f"[=] Trying Type-6 key candidate {name}: {kb.hex()}")
                try:
                    enc = aes_ecb_encrypt(comp, kb)
                    # quick decrypt check
                    dec = aes_ecb_decrypt(enc, kb)
                    if dec == comp:
                        chosen_key_name, chosen_key = name, kb
                        encrypted_payload = enc
                        if verbose: print("[+] Type-6 key verifies")
                        break
                except Exception:
                    continue
            if encrypted_payload is None:
                # fallback choose first
                chosen_key_name, chosen_key = key_candidates[0]
                encrypted_payload = aes_ecb_encrypt(comp, chosen_key)

        else:
            raise ValueError("Unsupported payload type")

    # Compose final file
    if payload_type == 6:
        # Use template header and write payload len at offset
        hdr = bytearray(read_bytes(template_path))
        if len(hdr) < header_len:
            raise ValueError("Template header too small")
        # Keep only header_len bytes
        hdr = hdr[:header_len]
        update_type6_header(hdr, len(encrypted_payload), size_offset, payload_type=payload_type)
        out_bytes = bytes(hdr) + encrypted_payload
        write_bytes(out_path, out_bytes)
        if verbose:
            print(f"[+] Wrote type-6 file {out_path} total {len(out_bytes)} bytes (payload {len(encrypted_payload)})")
    else:
        # For other types we try to use zcu.zte.add_header if available, else make a simple wrapper
        if ZCU_AVAILABLE:
            # zcu expects a file-like; we have bytes
            import io
            data_stream = io.BytesIO(encrypted_payload if payload_type not in (0,1) else comp)
            encoded = zcu.zte.add_header(data_stream, (signature or "").encode("utf-8"), (2 << 16), include_header=True, little_endian=False)
            write_bytes(out_path, encoded.read())
            if verbose:
                print(f"[+] Wrote file with zcu header: {out_path} size={os.path.getsize(out_path)}")
        else:
            # fallback: simple header (not ZTE-specific) -> just write payload
            write_bytes(out_path, encrypted_payload if payload_type not in (0,1) else comp)
            if verbose:
                print(f"[+] Wrote raw payload to {out_path} (no zcu available)")

    # Verification: attempt to decrypt produced bin and compare to xml bytes
    try:
        if payload_type == 6:
            # decrypt using chosen_key
            dec = aes_ecb_decrypt(encrypted_payload, chosen_key)
            dec_uncomp = decompress_bytes(dec, compression)
            ok = dec_uncomp == xml_b
            if verbose:
                print(f"[+] Verification Type-6: {'OK' if ok else 'FAILED'}")
            return ok
        elif payload_type in (2,):
            dec = aes_ecb_decrypt(encrypted_payload, chosen_key)
            ok = dec == comp and decompress_bytes(dec, compression) == xml_b
            if verbose:
                print(f"[+] Verification Type-2: {'OK' if ok else 'FAILED'}")
            return ok
        elif payload_type in (3,4,5):
            dec = aes_cbc_decrypt(encrypted_payload, chosen_key, iv_bytes)
            dec_uncomp = decompress_bytes(dec, compression)
            ok = dec_uncomp == xml_b
            if verbose:
                print(f"[+] Verification CBC: {'OK' if ok else 'FAILED'}")
            return ok
        else:
            # type 0/1 raw
            dec_uncomp = decompress_bytes(encrypted_payload if payload_type in (0,1) else b"", compression)
            ok = dec_uncomp == xml_b
            if verbose:
                print(f"[+] Verification plain: {'OK' if ok else 'FAILED'}")
            return ok
    except Exception as e:
        if verbose:
            print("[!] Verification error:", e)
        return False

# ---------------- CLI ----------------
def main():
    p = argparse.ArgumentParser(description="ZTE universal encoder (payload types 0..6)")
    p.add_argument("--template", dest="template", help="Template config.bin (required for type-6)")
    p.add_argument("--header-len", type=lambda x:int(x,0), default=HEADER_LEN_DEFAULT, help="Header length to copy for type-6 (default 0x90)")
    p.add_argument("--size-offset", type=lambda x:int(x,0), default=SIZE_OFFSET_DEFAULT, help="Offset to write payload length in header (default 0x48)")
    p.add_argument("--xml", required=True, help="Input XML/plain data file (bytes unchanged)")
    p.add_argument("--out", required=True, help="Output config.bin")
    p.add_argument("--payload-type", type=int, choices=[0,1,2,3,4,5,6], default=0, help="Payload type (0..6)")
    p.add_argument("--compress", choices=["zlib","lzma","none"], default="zlib", help="Compression method")
    p.add_argument("--key", help="AES key (hex or ascii). If hex (even len) will be interpreted as raw bytes", default=None)
    p.add_argument("--iv", help="IV string (utf-8) or hex (if even hex len)", default=None)
    p.add_argument("--serial", help="Serial for kp derivation (for type-4/6)", default=None)
    p.add_argument("--mac", help="MAC for kp derivation (for type-4/6)", default=None)
    p.add_argument("--signature", help="Signature string for header or keygen", default=None)
    p.add_argument("--try-key-methods", action="store_true", help="Try several key derivation methods (kp-first16, kp-md5) if available")
    p.add_argument("--try-all-key-methods", action="store_true", help="Alias for --try-key-methods")
    p.add_argument("--verbose", action="store_true", help="Verbose")
    args = p.parse_args()

    # normalize key/iv arguments: accept hex or raw ascii
    key_bytes = None
    if args.key:
        k = args.key
        if all(c in "0123456789abcdefABCDEF" for c in k) and len(k) % 2 == 0:
            key_bytes = bytes.fromhex(k)
        else:
            key_bytes = k.encode("utf-8")

    iv_bytes = None
    if args.iv:
        v = args.iv
        if all(c in "0123456789abcdefABCDEF" for c in v) and len(v) % 2 == 0:
            iv_bytes = bytes.fromhex(v)
        else:
            iv_bytes = v.encode("utf-8")
    else:
        # default IV string
        iv_bytes = DEFAULT_IV_STR.encode("utf-8")

    ok = encode(
        xml_path=args.xml,
        out_path=args.out,
        payload_type=args.payload_type,
        compression=args.compress,
        key_bytes=key_bytes,
        iv_bytes=iv_bytes,
        serial=args.serial,
        mac=args.mac,
        signature=args.signature,
        template_path=args.template,
        header_len=args.header_len,
        size_offset=args.size_offset,
        try_key_methods=(args.try_key_methods or args.try_all_key_methods),
        verbose=args.verbose
    )
    if ok:
        print("[+] Encoding + verification succeeded.")
        return 0
    else:
        print("[!] Encoding finished but verification failed.")
        return 2

if __name__ == "__main__":
    sys.exit(main())
