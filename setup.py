"""
setup.py

setup file for the cs3client package.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 26/07/2024
"""

from setuptools import setup, find_packages
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

version = os.getenv("PACKAGE_VERSION", "0.0.0")

setup(
    name="cs3client",
    version=version,
    author="Rasmus Welander, Diogo Castro, Giuseppe Lo Presti",
    packages=find_packages(),
    description="CS3 client for Python",
    package_dir={"cs3client": "cs3client"},
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cs3org/cs3-python-client",
    install_requires=[
        "grpcio>=1.47.0",
        "grpcio-tools>=1.47.0",
        "pyOpenSSL",
        "requests",
        "cs3apis",
        "PyJWT",
        "protobuf",
        "cryptography",
    ],
)
