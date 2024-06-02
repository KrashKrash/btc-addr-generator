import ecdsa
from Crypto.Hash import RIPEMD160, SHA256
import base58

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

def public_key_to_address(public_key, compressed=True):
    sha = SHA256.new(public_key).digest()
    ripemd = RIPEMD160.new(sha).digest()
    network_byte = b'\x00'
    versioned_payload = network_byte + ripemd
    checksum_full = SHA256.new(SHA256.new(versioned_payload).digest()).digest()
    checksum = checksum_full[:4]
    binary_address = versioned_payload + checksum
    return base58.b58encode(binary_address).decode()

def generate_address_details():
    curve = ecdsa.SECP256k1
    private_key = ecdsa.SigningKey.generate(curve=curve)
    private_key_bytes = private_key.to_string()
    verifying_key = private_key.get_verifying_key()

    public_key_uncompressed = b'\x04' + verifying_key.to_string()
    public_key_compressed = (b'\x02' if int.from_bytes(verifying_key.to_string()[-32:], 'big') % 2 == 0 else b'\x03') + verifying_key.to_string()[:32]

    address_uncompressed = public_key_to_address(public_key_uncompressed, compressed=False)
    address_compressed = public_key_to_address(public_key_compressed, compressed=True)
    wif_uncompressed = private_key_to_wif(private_key_bytes, compressed=False)
    wif_compressed = private_key_to_wif(private_key_bytes, compressed=True)

    return {
        "private_key_hex": private_key_bytes.hex(),
        "private_key_decimal": int.from_bytes(private_key_bytes, 'big'),
        "wif_uncompressed": wif_uncompressed,
        "wif_compressed": wif_compressed,
        "public_key_uncompressed": public_key_uncompressed.hex(),
        "public_key_compressed": public_key_compressed.hex(),
        "btc_address_uncompressed": address_uncompressed,
        "btc_address_compressed": address_compressed
    }

# Printing header and ASCII art
print("By:")
print(logo)
print("This script is written by Krashfire\n")

# Open a file to write and print to console
with open('YourBitcoinInfo.txt', 'w') as file:
    file.write(logo + "\n")
    file.write("This code is written by KrashFire\n\n")
    
    for i in range(1, 11):
        details = generate_address_details()
        set_header = f"--------- Bitcoin Address Set {i} ---------"
        print(set_header)
        file.write(set_header + "\n")

        private_key_info = f"  Private Key (Hexadecimal): {details['private_key_hex']}\n" \
                           f"  Private Key (Decimal): {details['private_key_decimal']}"
        print(private_key_info)
        file.write(private_key_info + "\n")

        uncompressed_info = "\n  Uncompressed Bitcoin Address Details:\n" \
                            f"  Bitcoin Address: {details['btc_address_uncompressed']}\n" \
                            f"  Private Key (WIF): {details['wif_uncompressed']}\n" \
                            f"  Public Key: {details['public_key_uncompressed']}"
        print(uncompressed_info)
        file.write(uncompressed_info + "\n")

        compressed_info = "\n  Compressed Bitcoin Address Details:\n" \
                          f"  Bitcoin Address: {details['btc_address_compressed']}\n" \
                          f"  Private Key (WIF): {details['wif_compressed']}\n" \
                          f"  Public Key: {details['public_key_compressed']}"
        print(compressed_info)
        file.write(compressed_info + "\n")

        print("-" * len(set_header))  # Print a line to separate each set visually
        file.write("-" * len(set_header) + "\n")

# ANSI escape sequence for red color
start_red = '\033[91m'
reset_color = '\033[0m'

# Print the ASCII art in red
print("Coded By")
print(start_red + logo + reset_color)
print("---------------------------------------KRASHFIRE------------------------------------------")
