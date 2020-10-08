from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

import os

parametrs = dh.generate_parameters(
    generator=2, key_size=512, backend=default_backend())


class State:
    def __init__(self):
        self.DHs = None
        self.DHr = None
        self.RK = None
        self.CKr = None
        self.CKs = None
        self.Ns = None
        self.Nr = None
        self.PN = None
        self.MKSKIPPED = None

    def __str__(self):
        return f'{self.DHs}\n{self.DHr}\n{self.RK}\n{self.CKr}\n{self.CKs}\n{self.Ns}\n{self.Nr}\n{self.PN}\n{self.MKSKIPPED}\n'


def RatchetInitAlice(state, secret_key, bob_dh_public_key):
    state.DHs = GENERATE_DH()
    state.DHr = bob_dh_public_key
    state.RK, state.CKs = KDF_RK(secret_key, DH(state.DHs, state.DHr))
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}


def RatchetInitBob(state, secret_key, bob_dh_key_pair):
    state.DHs = bob_dh_key_pair
    state.DHr = None
    state.RK = secret_key
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}


def RatchetEncrypt(state, plaintext):
    state.CKs, msg_key = KDF_CK(state.CKs)
    header = {'public_key': state.DHs['public_key'], 'prev_num': state.PN,
              'msg_num': state.Ns}
    state.Ns += 1
    return header, encrypt(msg_key, plaintext)


def RatchetDecrypt(state, header, data):
    plaintext = trySkippedMessages(state, header, data)
    if plaintext != None:
        return plaintext
    if header['public_key'] != state.DHr:
        skipMessageKeys(state, header['prev_num'])
        DHRatchet(state, header)
    skipMessageKeys(state, header['msg_num'])
    state.CKr, msg_key = KDF_CK(state.CKr)
    state.Nr += 1
    return decrypt(msg_key, data)


def trySkippedMessages(state, header, data):
    if (header['public_key'], header['prev_num']) in state.MKSKIPPED:
        msg_key = state.MKSKIPPED[header['public_key'],
                                  header['msg_num']]
        del state.MKSKIPPED[header['public_key'], header['msg_num']]
        return decrypt(msg_key, data)
    else:
        return None


def skipMessageKeys(state, until):
    if state.Nr + 5 < until:
        print("ERROR!")
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, msg_key = KDF_CK(state.CKr)
            state.MKSKIPPED[state.DHr, state.Nr] = msg_key
            state.Nr += 1


def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header['public_key']
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))


def GENERATE_DH():
    private_key = parametrs.generate_private_key()
    public_key = private_key.public_key()
    return {'public_key': public_key, 'private_key': private_key}


def DH(dh_pair, dh_pub):
    return dh_pair['private_key'].exchange(dh_pub)


def KDF_RK(root_key, dh_out):
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=None,
        backend=default_backend()
    ).derive(dh_out)
    return key[0:32], key[32:64]


def KDF_CK(chain_key):
    h = hmac.HMAC(chain_key, hashes.SHA512(), backend=default_backend())
    h.update(b'0')
    result = h.finalize()
    return result[0:32], result[32:64]


def encrypt(key, plaintext):
    iv = os.urandom(16)
    padder = padding.PKCS7(256).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return {'iv': iv, 'ciphertext': ciphertext}


def decrypt(key, data):
    unpadder = padding.PKCS7(256).unpadder()
    decipher = Cipher(algorithms.AES(key), modes.CBC(
        data['iv']), backend=default_backend())
    decryptor = decipher.decryptor()
    plaintext = decryptor.update(data['ciphertext']) + decryptor.finalize()
    unpaddedData = unpadder.update(plaintext) + unpadder.finalize()
    return unpaddedData


def main():
    secret = os.urandom(32)
    bob_keys = GENERATE_DH()

    bob_state = State()
    alice_state = State()

    RatchetInitAlice(alice_state, secret, bob_keys['public_key'])
    RatchetInitBob(bob_state, secret, bob_keys)

    while (1):
        text = input("Co Alicja chce zaszyfrowac: ")
        header, data = RatchetEncrypt(alice_state, text)
        decrypted_text = RatchetDecrypt(bob_state, header, data)
        print(f'Bob odszyfrowuje: {decrypted_text.decode()}')

        text = input("Co Bob chce zaszyfrowac: ")
        header, data = RatchetEncrypt(bob_state, text)
        decrypted_text = RatchetDecrypt(alice_state, header, data)
        print(f'Alicja odszyfrowuje: {decrypted_text.decode()}')


if __name__ == '__main__':
    main()
