"""
checkpoints_api_example.py

Example script to demonstrate the usage of the checkpoint API in the CS3Client class.
note that these are examples, and is not meant to be run as a script.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 19/08/2024
"""

import logging
import configparser
from cs3client import CS3Client
from cs3resource import Resource

config = configparser.ConfigParser()
with open("default.conf") as fdef:
    config.read_file(fdef)
# log
log = logging.getLogger(__name__)

client = CS3Client(config, "cs3client", log)
# client.auth.set_token("<your_token_here>")
# OR
client.auth.set_client_secret("<your_client_secret_here>")

res = None

markdown_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/test.md")

res = client.checkpoint.list_file_versions(markdown_resource)

if res is not None:
    for ver in res:
        print(ver)

res = client.checkpoint.restore_file_version(markdown_resource, "1722936250.0569fa2f")
if res is not None:
    for ver in res:
        print(ver)
