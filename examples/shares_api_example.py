"""
shares_api_example.py

Example script to demonstrate the usage of the shares API in the CS3Client class.
note that these are examples, and is not meant to be run as a script.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 30/08/2024
"""

import logging
import configparser
from cs3client.cs3client import CS3Client
from cs3client.cs3resource import Resource
from cs3client.auth import Auth

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

res = None

# Create share #
resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/text.txt")
resource_info = client.file.stat(auth.get_token(), resource)

# VIEWER
user = client.user.get_user_by_claim("mail", "diogo.castro@cern.ch")
res = client.share.create_share(
    auth.get_token(), resource_info, user.id.opaque_id, user.id.idp, "VIEWER", "USER"
)
if res is not None:
    print(res)

# EDITOR
user = client.user.get_user_by_claim("username", "lopresti")
res = client.share.create_share(
    auth.get_token(), resource_info, user.id.opaque_id, user.id.idp, "EDITOR", "USER"
)
if res is not None:
    print(res)

# List existing shares #

# Create a filter list
filter_list = []
filter = client.share.create_share_filter(resource_id=resource_info.id, filter_type="TYPE_RESOURCE_ID")
filter_list.append(filter)
filter = client.share.create_share_filter(share_state="SHARE_STATE_PENDING", filter_type="TYPE_STATE")
filter_list.append(filter)
res, _ = client.share.list_existing_shares(auth.get_token(), filter_list=filter_list)
if res is not None:
    for share_info in res:
        print(share_info.share)

# Get share #
share_id = "58"
res = client.share.get_share(auth.get_token(), opaque_id=share_id)
if res is not None:
    print(res)

# update share #
share_id = "58"
res = client.share.update_share(auth.get_token(), opaque_id=share_id, role="VIEWER")
if res is not None:
    print(res)

# remove share #
share_id = "58"
res = client.share.remove_share(auth.get_token(), opaque_id=share_id)
if res is not None:
    print(res)

# List existing received shares #

# Create a filter list
filter_list = []
filter = client.share.create_share_filter(share_state="SHARE_STATE_ACCEPTED", filter_type="TYPE_STATE")

# Append the filter to the filter list
filter_list.append(filter)

# NOTE: filters for received shares are not implemented (14/08/2024), therefore it is left out
res, _ = client.share.list_received_existing_shares(auth.get_token())
if res is not None:
    for share_info in res:
        print(share_info.received_share)

# get received share #
share_id = "43"

received_share = client.share.get_received_share(auth.get_token(), opaque_id=share_id)
if received_share is not None:
    print(received_share)

# update recieved share #
res = client.share.update_received_share(
    auth.get_token(), received_share=received_share, state="SHARE_STATE_ACCEPTED"
)
if res is not None:
    print(res)

# create public share #
res = client.share.create_public_share(auth.get_token(), resource_info, role="VIEWER")
if res is not None:
    print(res)

# list existing public shares #

# Create a filter list
filter_list = []
filter = client.share.create_public_share_filter(resource_id=resource_info.id, filter_type="TYPE_RESOURCE_ID")
filter_list.append(filter)
print(filter_list)
res, _ = client.share.list_existing_public_shares(auth.get_token(), filter_list=filter_list)
if res is not None:
    for share_info in res:
        print(share_info.share)

# get public share #
share_id = "63"
# OR
token = "7FbP1EBXJQTqK0d"
res = client.share.get_public_share(auth.get_token(), opaque_id=share_id, sign=True)
if res is not None:
    print(res)

# update public share #
res = client.share.update_public_share(
    auth.get_token(), type="TYPE_PASSWORD", token=token, role="VIEWER", password="hello"
)
if res is not None:
    print(res)

# remove public share #
res = client.share.remove_public_share(auth.get_token(), token=token)
if res is not None:
    print(res)
