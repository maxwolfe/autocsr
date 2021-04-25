"""Command line utilities for autocsr."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Tuple

import click
import typer
from cryptography import x509

import autocsr.protos.csr_pb2 as proto
from autocsr import CertificateSigningRequestBuilder, load_csrs_from_file

app = typer.Typer()


class HashType(str, Enum):
    """Command line inputs for possible hash types."""

    sha256 = "SHA256"
    sha224 = "SHA224"
    sha384 = "SHA384"
    sha512 = "SHA512"
    sha512_224 = "SHA512_224"
    sha512_256 = "SHA512_256"
    blake2b = "BLAKE2b"
    blake2s = "BLAKE2s"
    sha3_224 = "SHA3_224"
    sha3_256 = "SHA3_256"
    sha3_384 = "SHA3_384"
    sha3_512 = "SHA3_512"
    shake128 = "SHAKE128"
    shake256 = "SHAKE256"


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


@dataclass
class OptionalParams:
    """A collection of optional parameters for CSRs."""

    hash_type: HashType
    country_name: str
    state_or_province_name: str
    locality_name: str
    organization_name: str
    organizational_unit_name: str
    email_address: str
    key_type: KeyType = KeyType.rsa
    key_size: int = 2048
    curve: Curve = Curve.secp256r1


def create_csr(
    common_name: str,
    key_path: str,
    output_path: str,
    create_key: bool,
    hash_type: HashType,
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
    csr_proto.hash_type = getattr(proto.CertificateSigningRequest.HashType, hash_type)

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

    csr = CertificateSigningRequestBuilder.from_proto(csr_proto)
    csr.export(csr_proto.output_path)

    return csr


def prompt_mandatory(
    common_name: str, key_path: str, output_path: str
) -> Tuple[str, str]:
    """Prompt the mandatory data for creating CSRs."""
    if not key_path:
        key_path = typer.prompt(
            "Where to store the new key?",
            default=f"./{common_name}.pem",
        )

    if not output_path:
        output_path = typer.prompt(
            "Where to store the new csr?",
            default=f"./{common_name}.csr",
        )

    return key_path, output_path


def prompt_optional(
    create_key: bool,
    country_name: str,
    state_or_province_name: str,
    locality_name: str,
    organization_name: str,
    organizational_unit_name: str,
    email_address: str,
) -> OptionalParams:
    """Prompt the optional data for creating CSRs."""
    if not country_name:
        country_name = typer.prompt(
            "What is your country identifier? (2 characters)",
            default="",
        )

    if not state_or_province_name:
        state_or_province_name = typer.prompt(
            "What is your state or province name?",
            default="",
        )

    if not locality_name:
        locality_name = typer.prompt(
            "What is your locality name?",
            default="",
        )

    if not organization_name:
        organization_name = typer.prompt(
            "What is your organization name?",
            default="",
        )

    if not organizational_unit_name:
        organizational_unit_name = typer.prompt(
            "What is your organizational unit name?",
            default="",
        )

    if not email_address:
        email_address = typer.prompt(
            "What is your email address?",
            default="",
        )

    hash_type = typer.prompt(
        "What is the desired hash algorithm to use?",
        default=HashType.sha256,
        type=click.Choice([h.value for h in HashType]),
    )

    params = OptionalParams(
        hash_type=hash_type,
        country_name=country_name,
        state_or_province_name=state_or_province_name,
        locality_name=locality_name,
        organization_name=organization_name,
        organizational_unit_name=organizational_unit_name,
        email_address=email_address,
    )

    if create_key:
        key_type = typer.prompt(
            "What is the desired type of key?",
            default=KeyType.rsa,
            type=click.Choice([k.value for k in KeyType]),
        )

        if key_type == KeyType.ec:
            curve = typer.prompt(
                "What is the desired elliptic curve?",
                default=Curve.secp256r1,
                type=click.Choice([c.value for c in Curve]),
            )
            params.curve = curve
        else:
            key_size = typer.prompt(
                "What is the desired key size?",
                default=2048,
                type=click.Choice([1024, 2048, 4096]),
            )
            params.key_size = key_size

    return params


@app.command()
def prompt(
    common_name: str,
    key_path: str = typer.Option("", help="Path to existing key"),
    output_path: str = typer.Option("", help="Desired output path"),
    hash_type: HashType = typer.Option(HashType.sha256, help="Hash algorithm to use"),
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
    """Prompt the user for Certificate Signing Request fields."""
    key_path, output_path = prompt_mandatory(common_name, key_path, output_path)
    create_key = not Path(key_path).exists()
    params = prompt_optional(
        create_key,
        country_name,
        state_or_province_name,
        locality_name,
        organization_name,
        organizational_unit_name,
        email_address,
    )

    create_csr(
        common_name=common_name,
        key_path=key_path,
        output_path=output_path,
        create_key=create_key,
        hash_type=params.hash_type,
        key_type=params.key_type,
        key_size=params.key_size,
        public_exponent=public_exponent,
        curve=params.curve,
        country_name=params.country_name,
        state_or_province_name=params.state_or_province_name,
        locality_name=params.locality_name,
        organization_name=params.organization_name,
        organizational_unit_name=params.organizational_unit_name,
        email_address=params.email_address,
    )
    typer.echo(f"Created new CSR at {output_path}")


@app.command()
def create(
    common_name: str,
    key_path: str = typer.Option("", help="Path to existing key"),
    output_path: str = typer.Option("", help="Desired output path"),
    hash_type: HashType = typer.Option(HashType.sha256, help="Hash algorithm to use"),
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
    """Create a new Certificate Signing Request with little customization."""
    key_path, output_path = prompt_mandatory(common_name, key_path, output_path)
    create_key = not Path(key_path).exists()

    create_csr(
        common_name=common_name,
        key_path=key_path,
        output_path=output_path,
        create_key=create_key,
        hash_type=hash_type,
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


@app.command()
def build(
    config_file: str,
):
    """Create certificate signing requests from a config file."""
    csr_list = load_csrs_from_file(config_file)

    for csr_proto in csr_list:
        csr = CertificateSigningRequestBuilder.from_proto(csr_proto)
        csr.export(csr_proto.output_path)
        typer.echo(f"Created new CSR at {csr_proto.output_path}")


def main():
    """Entrypoint to executable script."""
    app()
