"""
Utilities for common usage
"""

import json
import os
import pathlib
from typing import Generator, List

import yaml
from google.protobuf import json_format
from jinja2 import Environment, FileSystemLoader

from autocsr.protos.csr_pb2 import CertificateSigningRequest

CsrList = Generator[CertificateSigningRequest, None, None]


def load_csr(csr: dict) -> CertificateSigningRequest:
    """
    Load a CSR from a dictionary
    """

    return json_format.Parse(json.dumps(csr), CertificateSigningRequest())


def load_csrs_from_yaml(config_file: str) -> CsrList:
    """
    Load a CSR from a YAML file
    """

    with open(config_file, "r") as config:
        config_csrs = yaml.safe_load(config.read())

        for csr in config_csrs.values():
            yield load_csr(csr)


def use_env_variable(key: str) -> str:
    """
    Jinja filter to utilize environment variables
    """

    return os.environ[key]


def load_csrs_from_jinja(config_file: str) -> CsrList:
    """
    Load a CSR from a Jinja template
    """

    config_path = pathlib.Path(config_file)
    env = Environment(loader=FileSystemLoader(str(config_path.parent)))
    env.filters["env"] = use_env_variable

    config_template = env.get_template(config_path.name)
    config_csrs = yaml.safe_load(config_template.render())

    for csr in config_csrs.values():
        yield load_csr(csr)


def load_csrs_from_file(config_file: str) -> List[CertificateSigningRequest]:
    """
    Load all CSRs from a file
    """

    if config_file.endswith(".yaml"):
        return load_csrs_from_yaml(config_file)

    if config_file.endswith(".jinja2"):
        return load_csrs_from_jinja(config_file)

    raise TypeError(f"Config file type {config_file} is not supported")
