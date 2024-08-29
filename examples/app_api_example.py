"""
file_api_example.py

Example script to demonstrate the usage of the app API in the CS3Client class.
note that these are examples, and is not meant to be run as a script.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 28/08/2024
"""

import logging
import configparser
from cs3client.cs3client import CS3Client
from cs3client.cs3resource import Resource

config = configparser.ConfigParser()
with open("default.conf") as fdef:
    config.read_file(fdef)
log = logging.getLogger(__name__)

client = CS3Client(config, "cs3client", log)
client.auth.set_client_secret("<your_client_secret_here>")

# list_app_providers
res = client.app.list_app_providers(client.auth.get_token())
if res is not None:
    print(res)

# open_in_app
resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/collabora.odt")
res = client.app.open_in_app(client.auth.get_token(), resource)
if res is not None:
    print(res)
