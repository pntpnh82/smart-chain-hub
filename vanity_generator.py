"""
Vanity Generator — создает Bitcoin-адреса с заданным префиксом.
"""

import argparse
import time
import secrets
import base58
import hashlib
import ecdsa

def generate_keypair():
    private_key = secrets.token_bytes(32)
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()
    return private_key, public_key

def pubkey_to_address(public_key):
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    prefix = b'\x00'  # mainnet
    payload = prefix + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum)
    return address.decode()

def generate_vanity_address(prefix):
    attempts = 0
    start_time = time.time()
    while True:
        private_key, public_key = generate_keypair()
        address = pubkey_to_address(public_key)
        attempts += 1
        if address.startswith(prefix):
            duration = time.time() - start_time
            print(f"✅ Найдено за {attempts} попыток за {duration:.2f} сек")
            print(f"🔐 Приватный ключ: {private_key.hex()}")
            print(f"🏦 Адрес: {address}")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vanity Generator — создаёт кастомные Bitcoin-адреса.")
    parser.add_argument("prefix", help="Префикс адреса, например: 1Cool")
    args = parser.parse_args()

    if not args.prefix.startswith("1"):
        print("❗ Vanity-адрес должен начинаться с '1'")
    else:
        generate_vanity_address(args.prefix)
