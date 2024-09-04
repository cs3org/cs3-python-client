"""
lock_example.py

Example script to demonstrate the usage of the app API in the CS3Client class.
note that these are examples, and is not meant to be run as a script.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 30/08/2024
"""

import logging
import configparser
from cs3client.cs3client import CS3Client
from cs3client.auth import Auth
from cs3client.cs3resource import Resource


config = configparser.ConfigParser()
with open("default.conf") as fdef:
    config.read_file(fdef)
log = logging.getLogger(__name__)

client = CS3Client(config, "cs3client", log)
auth = Auth(client)
# Set the client id (can also be set in the config)
auth.set_client_id("<your_client_id_here>")
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

resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/lock_test.txt")

# Set lock
client.file.set_lock(auth_token, resource, app_name="a", lock_id="some_lock")

# Get lock
res = client.file.get_lock(auth_token, resource)
if res is not None:
    lock_id = res["lock_id"]
    print(res)

# Unlock
res = client.file.unlock(auth_token, resource, app_name="a", lock_id=lock_id)

# Refresh lock
client.file.set_lock(auth_token, resource, app_name="a", lock_id="some_lock")
res = client.file.refresh_lock(
    auth_token, resource, app_name="a", lock_id="new_lock", existing_lock_id=lock_id
)

if res is not None:
    print(res)

res = client.file.get_lock(auth_token, resource)
if res is not None:
    print(res)
