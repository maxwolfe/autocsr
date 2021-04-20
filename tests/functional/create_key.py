"""Create PKCS11 Key."""

import pkcs11
from pkcs11.util.ec import encode_named_curve_parameters


if __name__ == "__main__":
    lib = pkcs11.lib("/usr/lib/softhsm/libsofthsm2.so")
    token = lib.get_token(token_label="token")

    with token.open(rw=True, user_pin="1234") as session:
        session.generate_keypair(pkcs11.KeyType.RSA, 2048, label="rsa_key", store=True)

        session.generate_keypair(pkcs11.KeyType.DSA, 2048, label="dsa_key", store=True)
        # params = session.generate_domain_parameters(pkcs11.KeyType.DSA, 2048, store=True)
        # params.generate_keypair(label="dsa_key", store=True)

        params = session.create_domain_parameters(pkcs11.KeyType.EC, {
            pkcs11.Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")}, local=True)
        params.generate_keypair(label="ec_key", store=True)
