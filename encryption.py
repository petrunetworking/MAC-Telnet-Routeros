from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.Protocol.KDF import HKDF

def gen_stream_keys(server: bool, z: bytes):
    #### Compute receive and send keys ####
    magic2 = b"On the client side, this is the send key; on the server side, it is the receive key."
    magic3 = b"On the client side, this is the receive key; on the server side, it is the send key."

    if server:
        txEnc = z + b'\x00' * 40 + magic3 + b'\xf2' * 40
        rxEnc = z + b'\x00' * 40 + magic2 + b'\xf2' * 40
    else:
        txEnc = z + b'\x00' * 40 + magic2 + b'\xf2' * 40
        rxEnc = z + b'\x00' * 40 + magic3 + b'\xf2' * 40

    # Compute SHA-1 hash of the concatenated values
    sha = SHA1.new()
    sha.update(rxEnc)
    rxEnc = sha.digest()[:16]
    sha = SHA1.new()
    sha.update(txEnc)
    txEnc = sha.digest()[:16]

    # Parse keys from HKDF output
    send_key = hkdf_extract_and_expand(txEnc)
    send_aes_key = send_key[:0x10]
    send_hmac_key = send_key[0x10:]

    receive_key = hkdf_extract_and_expand(rxEnc)
    receive_aes_key = receive_key[:0x10]
    receive_hmac_key = receive_key[0x10:]

    return send_aes_key, receive_aes_key, send_hmac_key, receive_hmac_key

def hkdf_extract_and_expand(key_material: bytes, salt: bytes = b'\x00' * 0x40, info: bytes = b'', length: int = 0x24):
    prk = HMAC.new(salt, key_material, SHA1).digest()
    okm = b''
    previous_block = b''
    block_index = 1

    while len(okm) < length:
        hmac = HMAC.new(prk, previous_block + info + block_index.to_bytes(1, 'big'), SHA1)
        previous_block = hmac.digest()
        okm += previous_block
        block_index += 1

    return okm[:length]

def get_sha2_digest(input: bytes) -> bytes:
    sha = SHA256.new()
    sha.update(input)
    return sha.digest()
