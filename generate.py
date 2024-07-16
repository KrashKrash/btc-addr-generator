import ecdsa
from Crypto.Hash import RIPEMD160, SHA256
import base58
import hashlib
import sha3
import bech32


def private_key_to_wif(private_key_bytes, compressed=True):
    wif_bytes = b'\x80' + private_key_bytes
    if compressed:
        wif_bytes += b'\x01'
    hash1 = SHA256.new(wif_bytes).digest()
    hash2 = SHA256.new(hash1).digest()
    wif_bytes += hash2[:4]
    return base58.b58encode(wif_bytes).decode()

def public_key_to_p2pkh(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = RIPEMD160.new(sha256_bpk).digest()
    versioned_payload = b'\x00' + ripemd160_bpk
    checksum_full = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()
    checksum = checksum_full[:4]
    binary_address = versioned_payload + checksum
    return base58.b58encode(binary_address).decode()

def public_key_to_p2sh_segwit_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = RIPEMD160.new(sha256_bpk).digest()
    redeem_script = b'\x00\x14' + ripemd160_bpk
    redeem_script_hash = RIPEMD160.new(hashlib.sha256(redeem_script).digest()).digest()
    versioned_payload = b'\x05' + redeem_script_hash
    checksum_full = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()
    checksum = checksum_full[:4]
    binary_address = versioned_payload + checksum
    return base58.b58encode(binary_address).decode()

def public_key_to_bech32_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = RIPEMD160.new(sha256_bpk).digest()
    converted_address = bech32.convertbits(ripemd160_bpk, 8, 5)
    bech32_address = bech32.bech32_encode('bc', [0] + converted_address)
    return bech32_address

def public_key_to_bech32m_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    converted_address = bech32.convertbits(sha256_bpk, 8, 5)
    bech32m_address = bech32.bech32_encode('bc', [1] + converted_address)
    return bech32m_address

def generate_p2tr_address(public_key):
    taproot_version = [0x01]  # Taproot uses version 1 (Bech32m)
    taproot_data = bech32.convertbits(public_key, 8, 5)
    return bech32.bech32_encode('bc', taproot_version + taproot_data)

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

    btc_address_p2pkh_uncompressed = public_key_to_p2pkh(public_key_uncompressed)
    btc_address_p2pkh_compressed = public_key_to_p2pkh(public_key_compressed)
    btc_address_p2sh = public_key_to_p2sh_segwit_address(public_key_compressed)
    btc_address_bech32 = public_key_to_bech32_address(public_key_compressed)
    btc_address_bech32m = public_key_to_bech32m_address(public_key_compressed)
    btc_address_p2tr = generate_p2tr_address(public_key_compressed)

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
        "btc_address_p2pkh_uncompressed": btc_address_p2pkh_uncompressed,
        "btc_address_p2pkh_compressed": btc_address_p2pkh_compressed,
        "btc_address_p2sh": btc_address_p2sh,
        "btc_address_bech32": btc_address_bech32,
        "btc_address_bech32m": btc_address_bech32m,
        "btc_address_p2tr": btc_address_p2tr,
        "eth_address": eth_address
    }


# Open file & print to console
with open('YourCryptoInfo.txt', 'w') as file:
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

  Bitcoin P2PKH (Legacy) Address:
  - Uncompressed: {details['btc_address_p2pkh_uncompressed']}
  - Compressed: {details['btc_address_p2pkh_compressed']}

  Bitcoin P2SH-Segwit Address:
  - Bitcoin Address: {details['btc_address_p2sh']}

  Bitcoin Bech32 (Native Segwit v0) Address:
  - Bitcoin Address: {details['btc_address_bech32']}

  Bitcoin Bech32m (Native Segwit v1) Address:
  - Bitcoin Address: {details['btc_address_bech32m']}
  
  Bitcoin P2TR (Taproot) Address:
  - Bitcoin Address: {details['btc_address_p2tr']}

  Ethereum Address:
  - Ethereum Address: {details['eth_address']}

  WIF Private Keys:
  - Uncompressed: {details['wif_uncompressed']}
  - Compressed: {details['wif_compressed']}

  Public Keys:
  - Uncompressed: {details['public_key_uncompressed']}
  - Compressed: {details['public_key_compressed']}
"""
        print(address_info)
        file.write(address_info + "\n")

        print("-" * len(set_header)) 
        file.write("-" * len(set_header) + "\n")

print("Coded By")
print("---------------------------------------KRASHFIRE------------------------------------------")
