[![Build Status](https://travis-ci.com/maxwolfe/autocsr.svg?token=qz3Kxzoztoakrxm4CFDZ&branch=master)](https://travis-ci.com/maxwolfe/autocsr)

# AutoCSR: Automatic Certificate Signing Request Generation

`AutoCSR` is a command-line tool and library for automatically generating Certificate Signing Requests from easy to define configuration files.

`AutoCSR` was developed to empower non-security professionals to quickly and easily generate their own simple Certificate Signing Requests with minimal security knowledge required.

`AutoCSR` also provides security professionals with the ability to define complex Certificate Signing Requests with templates that can be easily shared with non-security professionals to generate complex Certificate Signing Requests without the need for detailed instructions or handholding.

## Install
```
pip install autocsr
```

## Usage
```
Usage: autocsr [OPTIONS] CONFIG_FILE
```

## Quickstart

### Create a Config File
```
# quick_csr.yaml
My First CSR:
  subject:
    common_name: My first AutoCSR
  key_info:
    key_path: /tmp/my_first_key.key
    create: True
  output_path: /tmp/my_first_autocsr.csr
```

### Run AutoCSR
```
max@wolfetop:/app# autocsr quick_csr.yaml
Created new CSR at /tmp/my_first_autocsr.csr
```

### Validate New CSR
```
max@wolfetop:/app# openssl req -text -noout -verify -in /tmp/my_first_autocsr.csr
verify OK
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = My first AutoCSR
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:93:f6:52:6e:51:64:0a:a6:95:d5:89:71:11:bf:
                    50:c6:cc:54:e7:9a:06:ec:16:0a:3f:dc:8f:ee:57:
                    50:6f:bd:6b:92:89:50:d5:97:5c:74:ca:86:08:41:
                    52:af:13:5a:a9:8c:3d:79:64:14:77:fe:ef:52:d6:
                    57:6c:59:01:f4:02:03:a7:b0:c6:24:9c:1d:26:72:
                    15:f8:8b:58:25:85:83:b4:b4:26:7b:4f:db:59:93:
                    09:07:02:d3:8f:92:1d:d1:c6:94:9c:6a:06:77:de:
                    f5:5e:b8:4a:30:86:c5:6e:81:35:f4:cb:88:e7:79:
                    a3:91:22:c9:03:92:9c:8a:3a:3c:49:58:fe:18:e2:
                    e2:18:c3:6d:e0:a2:7d:21:62:80:dd:54:fb:4b:85:
                    ed:08:5f:10:0b:af:2e:66:bc:57:53:a3:d9:06:23:
                    ce:97:63:54:4c:8e:13:0f:01:1a:3e:9d:80:53:91:
                    71:f8:3f:93:03:41:d7:64:2b:5e:b6:d1:b8:17:bd:
                    10:6f:56:b5:d2:ec:3d:1a:91:0e:7a:2e:f2:ff:d4:
                    03:33:8b:91:48:6b:e3:e6:ea:f2:49:48:49:81:5a:
                    c7:b9:5a:ef:85:ce:71:61:28:7e:28:8c:07:23:48:
                    e3:c3:7e:74:46:bc:88:fa:84:9b:d3:16:98:9b:58:
                    29:9d
                Exponent: 65537 (0x10001)
        Attributes:
        Requested Extensions:
    Signature Algorithm: sha256WithRSAEncryption
         07:6c:ac:32:92:04:f2:57:42:8f:93:92:09:92:77:01:c6:5e:
         e4:7f:17:f6:78:fd:8a:83:8a:d7:55:3f:f1:c4:ba:09:1c:9e:
         2a:04:db:e3:2f:b9:c1:d0:49:53:59:47:6f:d0:3e:ae:c3:4d:
         96:f2:f0:f8:b2:9f:67:62:fc:4b:32:35:c7:f3:cc:78:83:d0:
         82:0a:b6:f0:90:83:12:10:73:49:36:ac:f2:27:85:91:b1:9d:
         0d:22:d7:2f:34:84:0a:2f:c1:d3:ee:62:82:72:78:64:93:17:
         83:7c:68:65:89:e5:ad:cc:e3:f0:c8:03:1e:18:c0:11:89:af:
         9f:5d:7a:23:a0:c9:c7:97:44:fd:18:40:6e:aa:02:cf:bb:8a:
         17:6c:24:64:3b:a5:9b:0c:c8:52:e1:8f:8f:83:ec:8b:14:5c:
         a7:38:83:f8:67:6b:2d:3e:1a:02:39:2a:57:27:3a:c0:62:b7:
         bc:90:6c:b6:f5:2c:32:f5:87:dc:b0:0c:b2:93:d3:2d:8d:cb:
         0b:a1:e6:70:aa:b9:67:bf:9b:89:ae:25:12:08:08:83:ee:7e:
         58:33:e6:53:37:fb:28:7c:79:98:39:bf:b4:8b:b9:e3:b5:75:
         8d:bd:b6:ce:e1:11:69:81:ab:37:d9:f0:3c:6e:35:b1:23:d8:
         6a:10:be:2e
```

## Creating Templates
A template is an overall definition of the data you want to be include in your Certificate Signing Request. Most fields can be optionally excluded or have safe default values for those who don't want to worry too much about the details.

### Subject
The subject of the Certificate Signing Request contains various metadata about the certificate, the only required portion being the `common_name`.

```
# subject_example.yaml
A Subject CSR:
  subject:
    common_name: All about the subject
    country_name: US
    state_or_province_name: California
    locality_name: Bay Area
    organization_name: SecurityWolfe
    organizational_unit_name: The Cool Team
    email_address: max@securitywolfe.com
  key_info:
    key_path: /tmp/subject_example.key
    create: True
  output_path: /tmp/subject_example.csr
```

#### Explicit Subject Example

```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = All about the subject, C = US, ST = California, L = Bay Area, O = SecurityWolfe, OU = The Cool Team, emailAddress = max@securitywolfe.com
```

### Key and Signing Information
`AutoCSR` allows keys to be generated on the fly or loaded directly from files. You can also explicitly define the hash algorithm to use for signing.

```
# key_example.yaml
RSA With Explicit Key Parameters:
  subject:
    common_name: RSA CSR with explicit key parameters
  key_info:
    key_path: /tmp/my_rsa.key
    create: True
    key_type: RSA
    key_size: 2048
    public_exponent: 65537
  hash_type: SHA256
  output_path: /tmp/my_rsa_autocsr.csr

DSA From Key File:
  subject:
    common_name: DSA CSR from key file
  key_info:
    key_path: /tmp/my_dsa.key
  output_path: /tmp/my_dsa_autocsr.csr

EC With Explicit Key Parameters:
  subject:
    common_name: EC CSR with explicit key parameters
  key_info:
    key_path: /tmp/my_ec.key
    create: True
    key_type: EC
    curve: SECP256R1
  hash_type: SHA512
  output_path: /tmp/my_ec_autocsr.csr
```

Running `autocsr` on this configuration file will generate three Certificate Signing Requests:

#### RSA Example CSR
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = RSA CSR with explicit key parameters
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus: ...
                Exponent: 65537 (0x10001)
        Attributes:
        Requested Extensions:
    Signature Algorithm: sha256WithRSAEncryption
```

#### DSA Example CSR
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = DSA CSR from key file
        Subject Public Key Info:
            Public Key Algorithm: dsaEncryption
                pub: ...
                P: ...
                Q: ...
                G: ...
        Attributes:
        Requested Extensions:
    Signature Algorithm: dsa_with_SHA256
```

#### EC Example CSR
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = EC CSR with explicit key parameters
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: ...
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        Attributes:
        Requested Extensions:
    Signature Algorithm: ecdsa-with-SHA512
```

### Attributes
Certificates can optionally contain a plethora of pre-defined and custom attributes which map an `oid` to a binary value. Because we primarily use YAML for our configuration files, we require that attribute values are base64 encoded in the config file when defining attributes. Optionally for predefined attributes, a string name can be used instead of the dotted-string `oid`.

```
# attribute_example.yaml
CSR with Attributes:
  subject:
    common_name: My CSR with custom and well-known attributes
  key_info:
    key_path: /tmp/my_attributes.key
    create: True
  output_path: /tmp/my_attributes_autocsr.csr
  attributes:
    - oid: issuerAltName
      b64_value: TXkgSXNzdWVyIEFsdCBOYW1l
    - oid: 1.2.345.678  # A custom OID
      b64_value: TXkgQ3VzdG9tIEF0dHJpYnV0ZQ==
```

#### Custom and Predefined Attributes Example

```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = My CSR with custom and well-known attributes
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus: ...
                Exponent: 65537 (0x10001)
        Attributes:
            X509v3 Issuer Alternative Name:My Issuer Alt Name
            1.2.345.678              :My Custom Attribute
```

### Extensions
Certificate Signing Requests offer a plethora of predefined extensions. An exhaustive list of the available extensions are available [here](https://cryptography.io/en/latest/x509/reference/#x-509-extensions), but I will provide a few examples of modeling extensions in configuration files below. Keep in mind that like attributes, extensions that require bytes as input will need to have their data represented in base64.

```
# extension_example.yaml
My CSR with Extensions:
  subject:
    common_name: Some Common Extensions for CSRs
  key_info:
    key_path: /tmp/my_extension_example.key
    create: True
  output_path: /tmp/my_extension_autocsr.csr
  extensions:
    - critical: True
      extension_type: OCSPNoCheck
    - critical: True
      subject_key_identifier:
        b64_digest: TXkgRXhhbXBsZSBTdWJqZWN0IEtleSBJZGVudGlmaWVy
    - critical: False
      extended_key_usage:
        usages:
          - "serverAuth"
          - "1.2.3.4.5"
    - critical: True
      key_usage:
        digital_signature: True
        content_commitment: False
        key_encipherment: True
        data_encipherment: False
        key_agreement: True
        key_cert_sign: False
        crl_sign: True
        encipher_only: False
        decipher_only: True
```

#### Various Extensions Example
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = Some Common Extensions for CSRs
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus: ...
                Exponent: 65537 (0x10001)
        Attributes:
        Requested Extensions:
            OCSP No Check: critical

            X509v3 Subject Key Identifier: critical
                4D:79:20:45:78:61:6D:70:6C:65:20:53:75:62:6A:65:63:74:20:4B:65:79:20:49:64:65:6E:74:69:66:69:65:72
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, 1.2.3.4.5
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Key Agreement, CRL Sign, Decipher Only
```

### Jinja Templates
Alternatively to using `.yaml` files, you can use `.jinja2` files modeled after YAML, but including environment variables to be replaced. If you wanted to recreate the first example using environment variables, you can do so like this:

```
# quick_csr.jinja2
{{ NAME }}'s First CSR:
  subject:
    common_name: {{ NAME }}'s first AutoCSR
  key_info:
    key_path: /tmp/{{ NAME }}s_first_key.key
    create: True
  output_path: /tmp/{{ NAME }}s_first_autocsr.csr
```

#### Run AutoCSR on a Jinja Template
```
max@wolfetop:/app# NAME=Max autocsr quick_csr.jinja2
Created new CSR at /tmp/Maxs_first_autocsr.csr
```

#### Validate Jinja Templated CSR
```
max@wolfetop:/app# openssl req -text -noout -verify -in /tmp/Maxs_first_autocsr.csr
verify OK
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = Max's first AutoCSR
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
```
