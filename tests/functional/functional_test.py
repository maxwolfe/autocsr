"""Example utilizing autocsr."""

import autocsr.csr
import autocsr.utils

if __name__ == "__main__":
    csrs = autocsr.utils.load_csrs_from_file("autocsr/tests/fixtures/test_config.yaml")

    for csr in csrs:
        my_csr = autocsr.csr.CertificateSigningRequestBuilder.from_csr(csr)

        assert my_csr.is_signature_valid, "Generated CSRs should be valid"
