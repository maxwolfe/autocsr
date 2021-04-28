"""Example utilizing autocsr."""

import autocsr.csr
import autocsr.utils

if __name__ == "__main__":
    csrs = autocsr.utils.load_csrs_from_file("tests/fixtures/test_config.yaml")

    for csr in csrs:
        my_csr = autocsr.csr.CertificateSigningRequestBuilder.from_proto(csr)

        print(csr.subject.common_name)
        assert my_csr.is_signature_valid, "Generated CSRs should be valid"
