"""
checkpoints_api_example.py

Example script to demonstrate the usage of the checkpoint API in the CS3Client class.
note that these are examples, and is not meant to be run as a script.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 30/08/2024
"""

import logging
import configparser
from cs3client.cs3resource import Resource
from cs3client.cs3client import CS3Client
from cs3client.auth import Auth

config = configparser.ConfigParser()
with open("default.conf") as fdef:
    config.read_file(fdef)
log = logging.getLogger(__name__)

client = CS3Client(config, "cs3client", log)
auth = Auth(client)
# Set client secret (can also be set in config)
auth.set_client_secret("<your_client_secret_here>")
# Checks if token is expired if not return ('x-access-token', <token>)
# if expired, request a new token from reva
auth_token = auth.get_token()

# OR if you already have a reva token
# Checks if token is expired if not return (x-access-token', <token>)
# if expired, throws an AuthenticationException (so you can refresh your reva token)
token = "<your_reva_token>"
auth_token = Auth.check_token(token)

res = None

markdown_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/test.md")

res = client.checkpoint.list_file_versions(auth.get_token(), markdown_resource)

if res is not None:
    for ver in res:
        print(ver)

res = client.checkpoint.restore_file_version(auth.get_token(), markdown_resource, "1722936250.0569fa2f")
if res is not None:
    for ver in res:
        print(ver)
