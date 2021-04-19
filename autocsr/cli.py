"""Command line utilities for autocsr."""

import typer

from autocsr import CertificateSigningRequestBuilder, load_csrs_from_file

app = typer.Typer()


@app.command()
def create(config_file: str):
    """Create Certificate signing requests from a config file."""
    csr_list = load_csrs_from_file(config_file)

    for csr_proto in csr_list:
        csr = CertificateSigningRequestBuilder.from_csr(csr_proto)
        csr.export(csr_proto.output_path)
        typer.echo(f"Created new CSR at {csr_proto.output_path}")


def main():
    """Entrypoint to executable script."""
    app()
