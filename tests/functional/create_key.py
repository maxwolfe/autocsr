"""Create PKCS11 Key."""

import pkcs11

if __name__ == "__main__":
    lib = pkcs11.lib("/usr/lib/softhsm/libsofthsm2.so")
    token = lib.get_token(token_label="token")

    with token.open(rw=True, user_pin="1234") as session:
        session.generate_keypair(
            pkcs11.KeyType.RSA, 2048, label="small_rsa_key", store=True
        )
        session.generate_keypair(
            pkcs11.KeyType.RSA, 4096, label="big_rsa_key", store=True
        )
