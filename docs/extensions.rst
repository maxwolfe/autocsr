Supported Extensions
====================

Below are a list of the extensions supported by ``AutoCSR``:

OCSPNoCheck
-----------

Example
~~~~~~~

::

    # ocsp_no_check_example.yaml
    OCSPNoCheckExtension:
      subject:
        common_name: OCSPNoCheck Example
      key_info:
        key_path: /tmp/ocsp_no_check_example.key
        create: True
      output_path: /tmp/ocsp_no_check_autocsr.csr
      extensions:
        - critical: True
          extension_type: OCSPNoCheck

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    enum ExtensionType {
      OCSPNoCheck = 0;
      PrecertPoison = 1;
    }

    ExtensionType extension_type = 2;

PrecertPoison
-------------

Example
~~~~~~~

::

    # precert_poison_example.yaml
    PrecertPoisonExtension:
      subject:
        common_name: PrecertPoison Example
      key_info:
        key_path: /tmp/precert_poison_example.key
        create: True
      output_path: /tmp/precert_poison_autocsr.csr
      extensions:
        - critical: True
          extension_type: PrecertPoison

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    enum ExtensionType {
      OCSPNoCheck = 0;
      PrecertPoison = 1;
    }

    ExtensionType extension_type = 2;

SubjectKeyIdentifier
--------------------

Example
~~~~~~~

::

    # subject_key_identifier_example.yaml
    SubjectKeyIdentifierExtension:
      subject:
        common_name: SubjectKeyIdentifier Example
      key_info:
        key_path: /tmp/subject_key_identifier_example.key
        create: True
      output_path: /tmp/subject_key_identifier_autocsr.csr
      extensions:
        - critical: True
          subject_key_identifier:
            b64_digest: "dGVzdA=="  # Base64 of "test"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message SubjectKeyIdentifier {
      string b64_digest = 1;
    }

    SubjectKeyIdentifier subject_key_identifier = 4;

BasicConstraints
----------------

Example
~~~~~~~

::

    # basic_constraints_example.yaml
    BasicConstraintsExtension:
      subject:
        common_name: BasicConstraints Example
      key_info:
        key_path: /tmp/basic_constraints_example.key
        create: True
      output_path: /tmp/basic_constraints_autocsr.csr
      extensions:
        - critical: True
          basic_constraints:
            ca: True
            path_length: 101

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message BasicConstraints {
      bool ca = 1;
      optional int32 path_length = 2;
    }

    BasicConstraints basic_constraints = 5;

PolicyConstraints
-----------------

Example
~~~~~~~

::

    # policy_constraints_example.yaml
    PolicyConstraintsExtension:
      subject:
        common_name: PolicyConstraints Example
      key_info:
        key_path: /tmp/policy_constraints_example.key
        create: True
      output_path: /tmp/policy_constraints_autocsr.csr
      extensions:
        - critical: True
          policy_constraints:
            require_explicit_policy: 102

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message PolicyConstraints {
      optional int32 require_explicit_policy = 1;
      optional int32 inhibit_policy_mapping = 2;
    }

    PolicyConstraints policy_constraints = 7;

CertificatePolicies
-------------------

Example
~~~~~~~

::

    # certificate_policies.yaml
    CertificatePoliciesExtension:
      subject:
        common_name: CertificatePolicies Example
      key_info:
        key_path: /tmp/certificate_policies_example.key
        create: True
      output_path: /tmp/certificate_policies_autocsr.csr
      extensions:
        - critical: True
          certificate_policies:
            policies:
              - policy_identifier: "1.2.3.4"
                string_qualifiers:
                  - "test qualifier 1"
                  - "test qualifier 2"
                user_qualifiers:
                  - notice_reference:
                      organization: "test_org"
                      notice_numbers:
                        - 1
                        - 2
                        - 3
                    explicit_text: "hello, test"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NoticeReference {
      optional string organization = 1;
      repeated int32 notice_numbers = 2;
    }

    message UserNotice {
      optional NoticeReference notice_reference = 1;
      optional string explicit_text = 2;
    }

    message PolicyInformation {
      string policy_identifier = 1;
      repeated string string_qualifiers = 2;
      repeated UserNotice user_qualifiers = 3;
    }

    message CertificatePolicies {
      repeated PolicyInformation policies = 1;
    }

    CertificatePolicies certificate_policies = 8;

Extended Key Usage
------------------

Example
~~~~~~~

::

    # extended_key_usage_example.yaml
    ExtendedKeyUsageExtension:
      subject:
        common_name: ExtendedKeyUsage Example
      key_info:
        key_path: /tmp/extended_key_usage_example.key
        create: True
      output_path: /tmp/extended_key_usage_autocsr.csr
      extensions:
        - critical: True
          extended_key_usage:
            usages:
              - "1.2.3.4.5"
              - "2.4.3.2.111"
              - "serverAuth"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message ExtendedKeyUsage {
      repeated string usages = 1;
    }

    ExtendedKeyUsage extended_key_usage = 9;

TLSFeature
----------

Example
~~~~~~~

::

    # tls_feature_example.yaml
    TLSFeatureExtension:
      subject:
        common_name: TLSFeature Example
      key_info:
        key_path: /tmp/tls_feature_example.key
        create: True
      output_path: /tmp/tls_feature_autocsr.csr
      extensions:
        - critical: True
          tls_feature:
            features:
              - "status_request"
              - "status_request_v2"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    enum TLSFeatureType {
      unused = 0;
      status_request = 5;
      status_request_v2 = 17;
    }

    message TLSFeature {
      repeated TLSFeatureType features = 1;
    }

    TLSFeature tls_feature = 10;

InhibitAnyPolicy
----------------

Example
~~~~~~~

::

    # inhibit_any_policy_example.yaml
    InhibitAnyPolicyExtension:
      subject:
        common_name: InhibitAnyPolicy Example
      key_info:
        key_path: /tmp/inhibit_any_policy_example.key
        create: True
      output_path: /tmp/inhibit_any_policy_autocsr.csr
      extensions:
        - critical: True
          inhibit_any_policy:
            skip_certs: 103

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message InhibitAnyPolicy {
      int32 skip_certs = 1;
    }

    InhibitAnyPolicy inhibit_any_policy = 11;

KeyUsage
--------

Example
~~~~~~~

::

    # key_usage_example.yaml
    KeyUsageExtension:
      subject:
        common_name: KeyUsage Example
      key_info:
        key_path: /tmp/key_usage_example.key
        create: True
      output_path: /tmp/key_usage_autocsr.csr
      extensions:
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

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message KeyUsage {
      bool digital_signature = 1;
      bool content_commitment = 2;
      bool key_encipherment = 3;
      bool data_encipherment = 4;
      bool key_agreement = 5;
      bool key_cert_sign = 6;
      bool crl_sign = 7;
      bool encipher_only = 8;
      bool decipher_only = 9;
    }

    KeyUsage key_usage = 12;

AuthorityKeyIdentifier
----------------------

Example
~~~~~~~

::

    # authority_key_identifier_example.yaml
    AuthorityKeyIdentifierExtension:
      subject:
        common_name: AuthorityKeyIdentifier Example
      key_info:
        key_path: /tmp/authority_key_identifier_example.key
        create: True
      output_path: /tmp/authority_key_identifier_autocsr.csr
      extensions:
        - critical: True
          authority_key_identifier:
            authority_cert_issuer:
              - rfc_822_name:
                  value: "Test RFC Name"
              - dns_name:
                  value: "Test DNS Name"
              - uniform_resource_identifier:
                  value: "Test Resource Name"
              - directory_name:
                  value:
                    attributes:
                      - oid: "1.2.3.4"
                        value: "test attribute"
              - registered_id:
                  oid: "1.3.4.5"
              - ip_address:
                  value: "123.12.2.43"
            authority_cert_serial_number: 5

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NameAttribute {
      string oid = 1;
      string value = 2;
    }

    message Name {
      repeated NameAttribute attributes = 1;
    }

    message RFC822Name {
      string value = 1;
    }

    message DNSName {
      string value = 1;
    }

    message UniformResourceIdentifier {
      string value = 1;
    }

    message DirectoryName {
      Name value = 1;
    }

    message RegisteredID {
      string oid = 1;
    }

    message IPAddress {
      string value = 1;
    }

    message OtherName {
      string oid = 1;
      string b64_value = 2;
    }

    message GeneralName {
      oneof name {
        RFC822Name rfc_822_name = 1;
        DNSName dns_name = 2;
        UniformResourceIdentifier uniform_resource_identifier = 3;
        DirectoryName directory_name = 4;
        RegisteredID registered_id = 5;
        IPAddress ip_address = 6;
        OtherName other_name = 7;
      }
    }

    message AuthorityKeyIdentifier {
      optional string key_identifier = 1;
      repeated GeneralName authority_cert_issuer = 2;
      optional int32 authority_cert_serial_number = 3;
    }

    AuthorityKeyIdentifier authority_key_identifier = 18;

AuthorityInformationAccess
--------------------------

Example
~~~~~~~

::

    # authority_information_access_example.yaml
    AuthorityInformationAccessExtension:
      subject:
        common_name: AuthorityInformationAccess Example
      key_info:
        key_path: /tmp/authority_information_access_example.key
        create: True
      output_path: /tmp/authority_information_access_autocsr.csr
      extensions:
        - critical: True
          authority_information_access:
            descriptions:
              - access_method: "1.4.5.6"
                access_location:
                  dns_name:
                    value: "Test DNS Access"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NameAttribute {
      string oid = 1;
      string value = 2;
    }

    message Name {
      repeated NameAttribute attributes = 1;
    }

    message RFC822Name {
      string value = 1;
    }

    message DNSName {
      string value = 1;
    }

    message UniformResourceIdentifier {
      string value = 1;
    }

    message DirectoryName {
      Name value = 1;
    }

    message RegisteredID {
      string oid = 1;
    }

    message IPAddress {
      string value = 1;
    }

    message OtherName {
      string oid = 1;
      string b64_value = 2;
    }

    message GeneralName {
      oneof name {
        RFC822Name rfc_822_name = 1;
        DNSName dns_name = 2;
        UniformResourceIdentifier uniform_resource_identifier = 3;
        DirectoryName directory_name = 4;
        RegisteredID registered_id = 5;
        IPAddress ip_address = 6;
        OtherName other_name = 7;
      }
    }

    message AccessDescription {
      string access_method = 1;
      GeneralName access_location = 2;
    }

    message AuthorityInformationAccess {
      repeated AccessDescription descriptions = 1;
    }

    AuthorityInformationAccess authority_information_access = 19;

SubjectInformationAccess
------------------------

Example
~~~~~~~

::

    # subject_information_access_example.yaml
    SubjectInformationAccessExtension:
      subject:
        common_name: SubjectInformationAccess Example
      key_info:
        key_path: /tmp/subject_information_access_example.key
        create: True
      output_path: /tmp/subject_information_access_autocsr.csr
      extensions:
        - critical: True
          subject_information_access:
            descriptions:
              - access_method: "1.9.5.6"
                access_location:
                  ip_address:
                    value: "11.22.33.44"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NameAttribute {
      string oid = 1;
      string value = 2;
    }

    message Name {
      repeated NameAttribute attributes = 1;
    }

    message RFC822Name {
      string value = 1;
    }

    message DNSName {
      string value = 1;
    }

    message UniformResourceIdentifier {
      string value = 1;
    }

    message DirectoryName {
      Name value = 1;
    }

    message RegisteredID {
      string oid = 1;
    }

    message IPAddress {
      string value = 1;
    }

    message OtherName {
      string oid = 1;
      string b64_value = 2;
    }

    message GeneralName {
      oneof name {
        RFC822Name rfc_822_name = 1;
        DNSName dns_name = 2;
        UniformResourceIdentifier uniform_resource_identifier = 3;
        DirectoryName directory_name = 4;
        RegisteredID registered_id = 5;
        IPAddress ip_address = 6;
        OtherName other_name = 7;
      }
    }

    message AccessDescription {
      string access_method = 1;
      GeneralName access_location = 2;
    }

    message SubjectInformationAccess {
      repeated AccessDescription descriptions = 1;
    }

    SubjectInformationAccess subject_information_access = 20;

CRLDistributionPoints
---------------------

Example
~~~~~~~

::

    # crl_distribution_points_example.yaml
    CRLDistributionPointsExtension:
      subject:
        common_name: CRLDistributionPoints Example
      key_info:
        key_path: /tmp/crl_distribution_points_example.key
        create: True
      output_path: /tmp/crl_distribution_points_autocsr.csr
      extensions:
        - critical: True
          crl_distribution_points:
            distribution_points:
              - relative_name:
                  attributes:
                  - oid: "1.8.8.8"
                    value: "relative_name"
                reasons:
                  - "superseded"
                  - "ca_compromise"
                crl_issuer:
                - dns_name:
                    value: "crl_issuer"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NameAttribute {
      string oid = 1;
      string value = 2;
    }

    message Name {
      repeated NameAttribute attributes = 1;
    }

    message RFC822Name {
      string value = 1;
    }

    message DNSName {
      string value = 1;
    }

    message UniformResourceIdentifier {
      string value = 1;
    }

    message DirectoryName {
      Name value = 1;
    }

    message RegisteredID {
      string oid = 1;
    }

    message IPAddress {
      string value = 1;
    }

    message OtherName {
      string oid = 1;
      string b64_value = 2;
    }

    message GeneralName {
      oneof name {
        RFC822Name rfc_822_name = 1;
        DNSName dns_name = 2;
        UniformResourceIdentifier uniform_resource_identifier = 3;
        DirectoryName directory_name = 4;
        RegisteredID registered_id = 5;
        IPAddress ip_address = 6;
        OtherName other_name = 7;
      }
    }

    enum ReasonFlags {
      unspecified = 0;
      key_compromise = 1;
      ca_compromise = 2;
      affiliation_changed = 3;
      superseded = 4;
      cessation_of_operation = 5;
      certificate_hold = 6;
      privilege_withdrawn = 7;
      aa_compromise = 8;
      remove_from_crl = 9;
    }

    message DistributionPoint {
      repeated GeneralName full_name = 1;
      optional Name relative_name = 2;
      repeated ReasonFlags reasons = 3;
      repeated GeneralName crl_issuer = 4;
    }

    message CRLDistributionPoints {
      repeated DistributionPoint distribution_points = 1;
    }

    CRLDistributionPoints crl_distribution_points = 21;

FreshestCRL
-----------

Example
~~~~~~~

::

    # freshest_crl_example.yaml
    FreshestCRLExtension:
      subject:
        common_name: FreshestCRL Example
      key_info:
        key_path: /tmp/freshest_crl_example.key
        create: True
      output_path: /tmp/freshest_crl_autocsr.csr
      extensions:
        - critical: True
          freshest_crl:
            distribution_points:
              - relative_name:
                  attributes:
                  - oid: "1.8.8.8"
                    value: "relative_name"
                reasons:
                  - "superseded"
                  - "ca_compromise"
                crl_issuer:
                - dns_name:
                    value: "crl_issuer"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NameAttribute {
      string oid = 1;
      string value = 2;
    }

    message Name {
      repeated NameAttribute attributes = 1;
    }

    message RFC822Name {
      string value = 1;
    }

    message DNSName {
      string value = 1;
    }

    message UniformResourceIdentifier {
      string value = 1;
    }

    message DirectoryName {
      Name value = 1;
    }

    message RegisteredID {
      string oid = 1;
    }

    message IPAddress {
      string value = 1;
    }

    message OtherName {
      string oid = 1;
      string b64_value = 2;
    }

    message GeneralName {
      oneof name {
        RFC822Name rfc_822_name = 1;
        DNSName dns_name = 2;
        UniformResourceIdentifier uniform_resource_identifier = 3;
        DirectoryName directory_name = 4;
        RegisteredID registered_id = 5;
        IPAddress ip_address = 6;
        OtherName other_name = 7;
      }
    }

    enum ReasonFlags {
      unspecified = 0;
      key_compromise = 1;
      ca_compromise = 2;
      affiliation_changed = 3;
      superseded = 4;
      cessation_of_operation = 5;
      certificate_hold = 6;
      privilege_withdrawn = 7;
      aa_compromise = 8;
      remove_from_crl = 9;
    }

    message DistributionPoint {
      repeated GeneralName full_name = 1;
      optional Name relative_name = 2;
      repeated ReasonFlags reasons = 3;
      repeated GeneralName crl_issuer = 4;
    }

    message FreshestCRL {
      repeated DistributionPoint distribution_points = 1;
    }

    FreshestCRL freshest_crl = 22;

NameConstraints
---------------

Example
~~~~~~~

::

    # name_constraints_example.yaml
    NameConstraintsExtension:
      subject:
        common_name: NameConstraints Example
      key_info:
        key_path: /tmp/name_constraints_example.key
        create: True
      output_path: /tmp/name_constraints_autocsr.csr
      extensions:
        - critical: True
          name_constraints:
            permitted_subtrees:
              - dns_name:
                  value: "permitted_subtrees"
            excluded_subtrees:
              - dns_name:
                  value: "excluded_subtrees"
              - dns_name:
                  value: "other excluded_subtrees"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NameAttribute {
      string oid = 1;
      string value = 2;
    }

    message Name {
      repeated NameAttribute attributes = 1;
    }

    message RFC822Name {
      string value = 1;
    }

    message DNSName {
      string value = 1;
    }

    message UniformResourceIdentifier {
      string value = 1;
    }

    message DirectoryName {
      Name value = 1;
    }

    message RegisteredID {
      string oid = 1;
    }

    message IPAddress {
      string value = 1;
    }

    message OtherName {
      string oid = 1;
      string b64_value = 2;
    }

    message GeneralName {
      oneof name {
        RFC822Name rfc_822_name = 1;
        DNSName dns_name = 2;
        UniformResourceIdentifier uniform_resource_identifier = 3;
        DirectoryName directory_name = 4;
        RegisteredID registered_id = 5;
        IPAddress ip_address = 6;
        OtherName other_name = 7;
      }
    }

    message NameConstraints {
      repeated GeneralName permitted_subtrees = 1;
      repeated GeneralName excluded_subtrees = 2;
    }

    NameConstraints name_constraints = 23;

SubjectAlternativeName
----------------------

Example
~~~~~~~

::

    # subject_alternative_name_example.yaml
    SubjectAlternativeNameExtension:
      subject:
        common_name: SubjectAlternativeName Example
      key_info:
        key_path: /tmp/subject_alternative_name_example.key
        create: True
      output_path: /tmp/subject_alternative_name_autocsr.csr
      extensions:
        - critical: True
          subject_alternative_name:
            general_names:
              - dns_name:
                  value: "first alternative name"
              - dns_name:
                  value: "second alternative name"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NameAttribute {
      string oid = 1;
      string value = 2;
    }

    message Name {
      repeated NameAttribute attributes = 1;
    }

    message RFC822Name {
      string value = 1;
    }

    message DNSName {
      string value = 1;
    }

    message UniformResourceIdentifier {
      string value = 1;
    }

    message DirectoryName {
      Name value = 1;
    }

    message RegisteredID {
      string oid = 1;
    }

    message IPAddress {
      string value = 1;
    }

    message OtherName {
      string oid = 1;
      string b64_value = 2;
    }

    message GeneralName {
      oneof name {
        RFC822Name rfc_822_name = 1;
        DNSName dns_name = 2;
        UniformResourceIdentifier uniform_resource_identifier = 3;
        DirectoryName directory_name = 4;
        RegisteredID registered_id = 5;
        IPAddress ip_address = 6;
        OtherName other_name = 7;
      }
    }

    message SubjectAlternativeName {
      repeated GeneralName general_names = 1;
    }

IssuerAlternativeName
---------------------

Example
~~~~~~~

::

    # issuer_alternative_name_example.yaml
    IssuerAlternativeNameExtension:
      subject:
        common_name: IssuerAlternativeName Example
      key_info:
        key_path: /tmp/issuer_alternative_name_example.key
        create: True
      output_path: /tmp/issuer_alternative_name_autocsr.csr
      extensions:
        - critical: True
          issuer_alternative_name:
            general_names:
              - dns_name:
                  value: "first issuer alternative name"
              - dns_name:
                  value: "second issuer alternative name"

Protobuf Definition
~~~~~~~~~~~~~~~~~~~

::

    message NameAttribute {
      string oid = 1;
      string value = 2;
    }

    message Name {
      repeated NameAttribute attributes = 1;
    }

    message RFC822Name {
      string value = 1;
    }

    message DNSName {
      string value = 1;
    }

    message UniformResourceIdentifier {
      string value = 1;
    }

    message DirectoryName {
      Name value = 1;
    }

    message RegisteredID {
      string oid = 1;
    }

    message IPAddress {
      string value = 1;
    }

    message OtherName {
      string oid = 1;
      string b64_value = 2;
    }

    message GeneralName {
      oneof name {
        RFC822Name rfc_822_name = 1;
        DNSName dns_name = 2;
        UniformResourceIdentifier uniform_resource_identifier = 3;
        DirectoryName directory_name = 4;
        RegisteredID registered_id = 5;
        IPAddress ip_address = 6;
        OtherName other_name = 7;
      }
    }

    message IssuerAlternativeName {
      repeated GeneralName general_names = 1;
    }

    IssuerAlternativeName issuer_alternative_name = 25;

