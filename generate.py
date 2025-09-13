import ecdsa, hashlib, base58, bech32

def pk_to_wif(pk_bytes, comp=True):
    wif = b'\x80' + pk_bytes
    if comp: wif += b'\x01'
    chk = hashlib.sha256(hashlib.sha256(wif).digest()).digest()[:4]
    return base58.b58encode(wif + chk).decode()

def h160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def h256(data):
    return hashlib.sha256(data).digest()

def keccak(data):
    k = hashlib.sha3_256()
    k.update(data)
    return k.digest()

def b58_enc(ver, payload):
    data = ver + payload
    chk = h256(h256(data))[:4]
    return base58.b58encode(data + chk).decode()

def pk_to_p2pkh(pk):
    return b58_enc(b'\x00', h160(pk))

def pk_to_p2sh(pk):
    redeem = b'\x00\x14' + h160(pk)
    return b58_enc(b'\x05', h160(redeem))

def pk_to_bech32(pk, ver, hrp='bc'):
    wp = h160(pk) if ver == 0 else h256(pk)
    conv = bech32.convertbits(wp, 8, 5)
    return bech32.bech32_encode(hrp, [ver] + conv)

def gen_p2tr_addr(pk):
    # For Taproot, use x-only public key (remove the first byte)
    x_only_pk = pk[1:] if pk[0] in [0x02, 0x03, 0x04] else pk
    
    # Tagged hash with "TapTweak" tag
    tag = b"TapTweak"
    tag_hash = h256(tag)
    tweak = h256(tag_hash + tag_hash + x_only_pk)
    
    # Convert to witness program
    wp = bytes([x_only_pk[i] ^ tweak[i] for i in range(32)])
    conv = bech32.convertbits(wp, 8, 5)
    return bech32.bech32_encode('bc', [1] + conv)

def gen_eth_addr(pk):
    kb = pk[1:] if pk[0] == 0x04 else pk
    return '0x' + keccak(kb)[-20:].hex()

def gen_addrs():
    curve = ecdsa.SECP256k1
    sk = ecdsa.SigningKey.generate(curve=curve)
    sk_bytes = sk.to_string()
    vk = sk.get_verifying_key()
    
    pk_u = b'\x04' + vk.to_string()
    y_parity = vk.to_string()[-32:]
    pk_c = (b'\x02' if int.from_bytes(y_parity, 'big') % 2 == 0 else b'\x03') + vk.to_string()[:32]
    
    return {
        "pk_hex": sk_bytes.hex(),
        "pk_dec": int.from_bytes(sk_bytes, 'big'),
        "wif_u": pk_to_wif(sk_bytes, False),
        "wif_c": pk_to_wif(sk_bytes, True),
        "pk_u": pk_u.hex(),
        "pk_c": pk_c.hex(),
        "p2pkh_u": pk_to_p2pkh(pk_u),
        "p2pkh_c": pk_to_p2pkh(pk_c),
        "p2sh": pk_to_p2sh(pk_c),
        "bech32": pk_to_bech32(pk_c, 0),
        "bech32m": pk_to_bech32(pk_c, 1),
        "p2tr": gen_p2tr_addr(pk_c),  # Use the correct Taproot function
        "eth": gen_eth_addr(pk_u)
    }

with open('CryptoInfo.txt', 'w') as f:
    f.write("By KrashFire\n\n")
    
    for i in range(1, 11):
        d = gen_addrs()
        hdr = f"--- Set {i} ---"
        print(hdr)
        f.write(hdr + "\n")
        
        info = f"""
  PK (Hex): {d['pk_hex']}
  PK (Dec): {d['pk_dec']}

  BTC P2PKH:
  - U: {d['p2pkh_u']}
  - C: {d['p2pkh_c']}

  P2SH: {d['p2sh']}
  Bech32: {d['bech32']}
  Bech32m: {d['bech32m']}
  P2TR: {d['p2tr']}
  ETH: {d['eth']}

  WIF:
  - U: {d['wif_u']}
  - C: {d['wif_c']}

  Public Keys:
  - U: {d['pk_u']}
  - C: {d['pk_c']}
"""
        print(info)
        f.write(info + "\n")
        f.write("-" * len(hdr) + "\n")
        print("-" * len(hdr))

print("By KRASHFIRE")
