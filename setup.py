"""
setup.py

setup file for the cs3client package.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 26/07/2024
"""

from setuptools import setup, find_packages

setup(
    name="cs3client",
    version="0.1",
    author="Rasmus Welander, Diogo Castro, Giuseppe Lo Presti",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    py_modules=["cs3client"],
    install_requires=[
        "grpcio>=1.47.0",
        "grpcio-tools>=1.47.0",
        "pyOpenSSL",
        "requests",
        "cs3apis>=0.1.dev101",
        "PyJWT",
        "protobuf",
        "cryptography",
    ],
)
