#!/usr/bin/env python3

import sys
from base64 import b64decode
from collections import namedtuple
from hashlib import sha256
from typing import List, Tuple


ECPublicKey = namedtuple("ECPublicKey", ["x", "y"])
ECSignature = namedtuple("ECSignature", ["r", "s"])
ECPrivateKey = namedtuple("ECPrivateKey", ["k"])


class BinaryExtractor:

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def extract_from_pattern(self, *pattern) -> Tuple[bytes, ...]:
        xtract = ()

        for tok in pattern:
            if tok[0] == 'x': # extract bytes
                if tok[1:].startswith("0x"):
                    read = int(tok[3:], 16)
                else:
                    read = int(tok[1:])
                xtract += (self.data[self.pos : self.pos + read],)
                self.pos += read

            elif tok[0] == 's': # skip bytes
                if tok[1:].startswith("0x"):
                    skip = int(tok[3:], 16)
                else:
                    skip = int(tok[1:])
                self.pos += skip

            else:
                byts = bytes.fromhex(tok)
                find = self.data.index(byts, self.pos)
                self.pos = find + len(byts)

        return xtract


class OpenSSL:

    @staticmethod
    def to_public_key(pubkey: ECPublicKey, alg: str = "prime256v1") -> bytes:
        if alg == "prime256v1" or alg == "secp256r1" or "p-256":
            return bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + pubkey.x + pubkey.y


    @staticmethod
    def to_private_key(privkey: ECPrivateKey, pubkey: ECPublicKey, alg: str = "prime256v1") -> bytes:
        if alg == "prime256v1" or alg == "secp256r1" or "p-256":
            return bytes.fromhex("30770201010420") + privkey.k + bytes.fromhex("a00a06082a8648ce3d030107a14403420004") + pubkey.x + pubkey.y


    @staticmethod
    def to_signature(sig: ECSignature, alg: str = "prime256v1") -> bytes:
        if alg == "prime256v1" or alg == "secp256r1" or "p-256":
            r = (bytes.fromhex("022100") if sig.r[0] > 0x7f else bytes.fromhex("0220")) + sig.r
            s = (bytes.fromhex("022100") if sig.s[0] > 0x7f else bytes.fromhex("0220")) + sig.s

            return bytes([0x30, len(r + s)]) + r + s


class CryptoExtractor:

    @staticmethod
    def bytes_from_file(file_path: str, from_base64: bool = True) -> bytes:
        with open(file_path, "rb") as f:
            return b64decode(f.read()) if from_base64 else f.read()


class Webauthn(CryptoExtractor):

    @staticmethod
    def extract_public_key(attestation_object: bytes = None, alg: str = "prime256v1",
                           from_file: str = None, from_base64: bool = True) -> ECPublicKey:
        if from_file:
            attestation_object = Webauthn.bytes_from_file(from_file, from_base64=from_base64)

        # As per webauthn spec: https://www.w3.org/TR/webauthn-2/#sctn-encoded-credPubKey-examples
        # (Examples of credentialPublicKey Values Encoded in COSE_Key Format)
        if alg == "prime256v1" or alg == "secp256r1" or "p-256":
            be = BinaryExtractor(attestation_object)
            x, y = be.extract_from_pattern("215820", "x32", "225820", "x32")

            return ECPublicKey(x, y)

        else:
            raise NotImplementedError()

    
    @staticmethod
    def create_verifiable_message(authenticator_data: bytes = None, client_data: bytes = None,
                                  from_files: Tuple[str, ...] = None, from_base64: bool = True) -> bytes:
        if from_files:
            authenticator_data = Webauthn.bytes_from_file(from_files[0], from_base64=from_base64)
            client_data = Webauthn.bytes_from_file(from_files[1], from_base64=from_base64)

        c_data_hash = sha256()
        c_data_hash.update(client_data)

        return authenticator_data + c_data_hash.digest()



class GPG(CryptoExtractor):

    @staticmethod
    def extract_public_key(public_key: bytes = None, alg: str = "prime256v1",
                           from_file: str = None, from_base64: bool = False) -> ECPublicKey:
        if from_file:
            public_key = GPG.bytes_from_file(from_file, from_base64=from_base64)

        # As per GPG spec: https://tools.ietf.org/html/rfc4880#section-5.5.2
        if alg == "prime256v1" or alg == "secp256r1" or "p-256":
            be = BinaryExtractor(public_key)
            x, y = be.extract_from_pattern("030107020304", "x32", "x32")

            return ECPublicKey(x, y)


    @staticmethod
    def extract_private_key(private_key: bytes = None, alg: str = "prime256v1",
                            from_file: str = None, from_base64: bool = False) -> ECPrivateKey:
        if from_file:
            private_key = GPG.bytes_from_file(from_file, from_base64=from_base64)

        # As per GPG spec: https://tools.ietf.org/html/rfc4880#section-5.5.1.3
        if alg == "prime256v1" or alg == "secp256r1" or "p-256":
            be = BinaryExtractor(private_key)
            k = be.extract_from_pattern("040000ff", "x32")[0]

            return ECPrivateKey(k)


    @staticmethod
    def extract_signature(signature: bytes = None, alg: str = "prime256v1",
                          from_file: str = None, from_base64: bool = False) -> ECSignature:
        if from_file:
            signature = GPG.bytes_from_file(from_file, from_base64=from_base64)

        # As per GPG spec: https://tools.ietf.org/html/rfc4880#page-19
        if alg == "prime256v1" or alg == "secp256r1" or "p-256":
            be = BinaryExtractor(signature)
            r, s = be.extract_from_pattern("s0x35", "x32", "s2", "x32")

            return ECSignature(r, s)


    @staticmethod
    def create_verifiable_message(message: bytes = None, gpg_sig: bytes = None,
                                  from_files: Tuple[str, ...] = None, from_base64: bool = False) -> bytes:
        if from_files:
            message = GPG.bytes_from_file(from_files[0], from_base64=from_base64)
            gpg_sig = GPG.bytes_from_file(from_files[1], from_base64=from_base64)

        be = BinaryExtractor(gpg_sig)
        gpg_sig_metadata = be.extract_from_pattern("8875", "x35")[0]

        return message + gpg_sig_metadata + bytes.fromhex("04ff000000") + bytes([len(gpg_sig_metadata)])


if __name__ == "__main__":

    # ===== Webauthn stuff ======
    # == Webauthn to OpenSSL public key ==
    #webauthn_pubkey = Webauthn.extract_public_key(from_file="./webauthn/register-attn-obj.b64")
    #sys.stdout.buffer.write(OpenSSL.to_public_key(webauthn_pubkey))

    # == Webauthn to OpenSSL verifiable message ==
    #sys.stdout.buffer.write(Webauthn.create_verifiable_message(from_files=("./webauthn/login-auth-data.b64", "./webauthn/login-client-data.b64")))

    # ===== GPG stuff ======
    # == GPG to OpenSSL public key ==
    #gpg_pubkey = GPG.extract_public_key(from_file="./gpg/r1.gpg.pub")
    #sys.stdout.buffer.write(OpenSSL.to_public_key(gpg_pubkey))

    # == GPG to OpenSSL signature and verifiable message
    #sig = GPG.extract_signature(from_file="./gpg/sig.gpg")
    #sys.stdout.buffer.write(OpenSSL.to_signature(sig))
    #sys.stdout.buffer.write(GPG.create_verifiable_message(from_files=("./gpg/msg.txt", "./gpg/sig.gpg")))

    # == GPG to OpenSSL private key
    gpg_pubkey = GPG.extract_public_key(from_file="./gpg/r1.gpg.pub")
    gpg_private = GPG.extract_private_key(from_file="./gpg/r1.gpg.priv")
    ossl_private = OpenSSL.to_private_key(gpg_private, gpg_pubkey)
    sys.stdout.buffer.write(ossl_private)