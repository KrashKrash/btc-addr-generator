import ecdsa
from Crypto.Hash import RIPEMD160, SHA256
import base58
import hashlib
import sha3
import bech32

# ASCII Art
logo = """
 ██████╗ ███████╗██████╗  █████╗ ████████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
 ██████╔╝█████╗  ██████╔╝███████║   ██║   ███████║███████║██║     ███████║█████╗  ██████╔╝
 ██╔══██╗██╔══╝  ██╔══██╗██╔══██║   ██║   ██╔══██║██╔══██║██║     ██╔══██║██╔══╝  ██╔══██╗
 ██║  ██║███████╗██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██║███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""

def private_key_to_wif(private_key_bytes, compressed=True):
    wif_bytes = b'\x80' + private_key_bytes
    if compressed:
        wif_bytes += b'\x01'
    hash1 = SHA256.new(wif_bytes).digest()
    hash2 = SHA256.new(hash1).digest()
    wif_bytes += hash2[:4]
    return base58.b58encode(wif_bytes).decode()

def public_key_to_address(public_key, prefix, compressed=True):
    sha = SHA256.new(public_key).digest()
    ripemd = RIPEMD160.new(sha).digest()
    versioned_payload = prefix + ripemd
    checksum_full = SHA256.new(SHA256.new(versioned_payload).digest()).digest()
    checksum = checksum_full[:4]
    binary_address = versioned_payload + checksum
    return base58.b58encode(binary_address).decode()

def public_key_to_bech32_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = RIPEMD160.new(sha256_bpk).digest()
    converted_address = bech32.convertbits(ripemd160_bpk, 8, 5)
    bech32_address = bech32.bech32_encode('bc', [0] + converted_address)
    return bech32_address

def generate_eth_address(public_key):
    keccak_hash = sha3.keccak_256()
    keccak_hash.update(public_key[1:])  # remove 0x04 prefix
    address = keccak_hash.digest()[-20:]
    return '0x' + address.hex()

def generate_address_details():
    curve = ecdsa.SECP256k1
    private_key = ecdsa.SigningKey.generate(curve=curve)
    private_key_bytes = private_key.to_string()
    verifying_key = private_key.get_verifying_key()

    public_key_uncompressed = b'\x04' + verifying_key.to_string()
    public_key_compressed = (b'\x02' if int.from_bytes(verifying_key.to_string()[-32:], 'big') % 2 == 0 else b'\x03') + verifying_key.to_string()[:32]

    btc_address_uncompressed = public_key_to_address(public_key_uncompressed, b'\x00', compressed=False)
    btc_address_compressed = public_key_to_address(public_key_compressed, b'\x00', compressed=True)
    btc_address_p2sh = public_key_to_address(public_key_uncompressed, b'\x05', compressed=False)
    btc_address_bech32 = public_key_to_bech32_address(public_key_compressed)

    eth_address = generate_eth_address(public_key_uncompressed)

    wif_uncompressed = private_key_to_wif(private_key_bytes, compressed=False)
    wif_compressed = private_key_to_wif(private_key_bytes, compressed=True)

    return {
        "private_key_hex": private_key_bytes.hex(),
        "private_key_decimal": int.from_bytes(private_key_bytes, 'big'),
        "wif_uncompressed": wif_uncompressed,
        "wif_compressed": wif_compressed,
        "public_key_uncompressed": public_key_uncompressed.hex(),
        "public_key_compressed": public_key_compressed.hex(),
        "btc_address_uncompressed": btc_address_uncompressed,
        "btc_address_compressed": btc_address_compressed,
        "btc_address_p2sh": btc_address_p2sh,
        "btc_address_bech32": btc_address_bech32,
        "eth_address": eth_address
    }

# Printing header and ASCII art
print("By:")
print(logo)
print("This script is written by Krashfire\n")

# Open a file to write and print to console
with open('YourCryptoInfo.txt', 'w') as file:
    file.write(logo + "\n")
    file.write("This code is written by KrashFire\n\n")
    
    for i in range(1, 11):
        details = generate_address_details()
        set_header = f"--------- Crypto Address Set {i} ---------"
        print(set_header)
        file.write(set_header + "\n")

        # Group and beautify the print statements
        address_info = f"""
  Private Key (Hexadecimal): {details['private_key_hex']}
  Private Key (Decimal): {details['private_key_decimal']}

  Uncompressed Bitcoin Address:
  - Bitcoin Address: {details['btc_address_uncompressed']}
  - Private Key (WIF): {details['wif_uncompressed']}
  - Public Key: {details['public_key_uncompressed']}

  Compressed Bitcoin Address:
  - Bitcoin Address: {details['btc_address_compressed']}
  - Private Key (WIF): {details['wif_compressed']}
  - Public Key: {details['public_key_compressed']}

  P2SH Bitcoin Address:
  - Bitcoin Address: {details['btc_address_p2sh']}

  Bech32 Bitcoin Address:
  - Bitcoin Address: {details['btc_address_bech32']}

  Ethereum Address:
  - Ethereum Address: {details['eth_address']}
"""
        print(address_info)
        file.write(address_info + "\n")

        print("-" * len(set_header))  # Print a line to separate each set visually
        file.write("-" * len(set_header) + "\n")

# ANSI escape sequence for red color
start_red = '\033[91m'
reset_color = '\033[0m'

# Print the ASCII art
print("Coded By")
print(start_red + logo + reset_color)
print("---------------------------------------KRASHFIRE------------------------------------------")
