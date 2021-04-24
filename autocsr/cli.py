"""Command line utilities for autocsr."""

from enum import Enum

import typer
from cryptography import x509

import autocsr.protos.csr_pb2 as proto
from autocsr import CertificateSigningRequestBuilder, load_csrs_from_file

app = typer.Typer()


class KeyType(str, Enum):
    """Command line inputs for possible key types."""

    rsa = "RSA"
    dsa = "DSA"
    ec = "EC"


class Curve(str, Enum):
    """Command line inputs for possible elliptic curve."""

    secp256r1 = "SECP256R1"
    secp384r1 = "SECP384R1"
    secp521r1 = "SECP521R1"
    secp192r1 = "SECP192R1"
    secp256k1 = "SECP256K1"
    brainpoolp256r1 = "BrainpoolP256R1"
    brainpoolp384r1 = "BrainpoolP384R1"
    brainpoolp512r1 = "BrainpoolP512R1"
    sect571k1 = "SECT571K1"
    sect409k1 = "SECT409K1"
    sect283k1 = "SECT283K1"
    sect233k1 = "SECT233K1"
    sect163k1 = "SECT163K1"
    sect571r1 = "SECT571R1"
    sect409r1 = "SECT409R1"
    sect283r1 = "SECT283R1"
    sect233r1 = "SECT233R1"
    sect163r2 = "SECT163R2"


def new_csr(
    common_name: str,
    key_path: str,
    output_path: str,
    create_key: bool,
    key_type: KeyType,
    key_size: int,
    public_exponent: int,
    curve: Curve,
    country_name: str,
    state_or_province_name: str,
    locality_name: str,
    organization_name: str,
    organizational_unit_name: str,
    email_address: str,
) -> x509.CertificateSigningRequest:
    """Create certificate signing requests from scratch."""
    csr_proto = proto.CertificateSigningRequest()
    csr_proto.output_path = output_path

    subject = proto.CertificateSigningRequest.Subject()
    subject.common_name = common_name
    subject.country_name = country_name
    subject.state_or_province_name = state_or_province_name
    subject.locality_name = locality_name
    subject.organization_name = organization_name
    subject.organizational_unit_name = organizational_unit_name
    subject.email_address = email_address
    csr_proto.subject.CopyFrom(subject)

    key_info = proto.CertificateSigningRequest.KeyInfo()
    key_info.key_path = key_path
    key_info.create = create_key
    key_info.key_type = getattr(proto.CertificateSigningRequest.KeyType, key_type)
    key_info.key_size = key_size
    key_info.public_exponent = public_exponent
    key_info.curve = getattr(proto.CertificateSigningRequest.Curve, curve)
    csr_proto.key_info.CopyFrom(key_info)

    csr = CertificateSigningRequestBuilder.from_csr(csr_proto)
    csr.export(csr_proto.output_path)

    return csr


@app.command()
def build(
    config_or_common_name: str,
    create: bool = typer.Option(False, help="Create a new key"),
    key_path: str = typer.Option("", help="Path to existing key"),
    output_path: str = typer.Option("", help="Desired output path"),
    key_type: KeyType = typer.Option(KeyType.rsa, help="Type of key to create"),
    key_size: int = typer.Option(2048, help="Bit size of key to create"),
    public_exponent: int = typer.Option(65537, help="Public exponent of key to create"),
    curve: Curve = typer.Option(
        Curve.secp256r1, help="Elliptic Curve of key to create"
    ),
    country_name: str = typer.Option("", help="Country name for CSR"),
    state_or_province_name: str = typer.Option(
        "", help="State or Province name for CSR"
    ),
    locality_name: str = typer.Option("", help="Locality name for CSR"),
    organization_name: str = typer.Option("", help="Organization name for CSR"),
    organizational_unit_name: str = typer.Option(
        "", help="Organizational unit name for CSR"
    ),
    email_address: str = typer.Option("", help="Email address for CSR"),
):
    """Create certificate signing requests from a config file."""
    if create:
        if key_path:
            create_key = False
        else:
            key_path = typer.prompt(
                "Where to store the new key?",
                default=f"./{config_or_common_name}.pem",
            )
            create_key = True

        if not output_path:
            output_path = typer.prompt(
                "Where to store the new csr?",
                default=f"./{config_or_common_name}.csr",
            )

        csr = new_csr(
            common_name=config_or_common_name,
            key_path=key_path,
            output_path=output_path,
            create_key=create_key,
            key_type=key_type,
            key_size=key_size,
            public_exponent=public_exponent,
            curve=curve,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
            organization_name=organization_name,
            organizational_unit_name=organizational_unit_name,
            email_address=email_address,
        )

        typer.echo(f"Created new CSR at {output_path}")
    else:
        csr_list = load_csrs_from_file(config_or_common_name)

        for csr_proto in csr_list:
            csr = CertificateSigningRequestBuilder.from_csr(csr_proto)
            csr.export(csr_proto.output_path)
            typer.echo(f"Created new CSR at {csr_proto.output_path}")


def main():
    """Entrypoint to executable script."""
    app()
