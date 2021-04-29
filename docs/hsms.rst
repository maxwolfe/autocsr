Supported HSMs
==============

Below are a list of the HSMs supported by ``AutoCSR``:

SoftHSM
-------

Example
~~~~~~~

::

    # softhsm_example.yaml
    My CSR from an HSM (SoftHSM):
      subject:
        common_name: A CSR Signed by SoftHSM
      hsm_info:
        softhsm:
          token_label: token
          key_label: small_rsa_key
          user_pin: "1234"
          so_file: /usr/lib/softhsm/libsofthsm2.so
        key_type: RSA
      output_path: /tmp/my_softhsm_autocsr.csr

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message SoftHsm {
      string token_label = 1;
      string key_label = 2;
      string user_pin = 3;
      string so_file = 4;
    }

    message HsmInfo {
      oneof hsm {
        SoftHsm softhsm = 1;
      }
      KeyType key_type = 2;
      optional int32 key_size = 3;
      optional int32 public_exponent = 4;
      optional Curve curve = 5;
    }

    oneof key {
      KeyInfo key_info = 2;
      HsmInfo hsm_info = 3;
    }

