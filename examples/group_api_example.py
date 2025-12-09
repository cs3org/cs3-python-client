"""
group_api_example.py

Example script to demonstrate the usage of the CS3Client class.


Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 08/12/2025
"""

import logging
import configparser
from cs3client.cs3client import CS3Client
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


# get_group_by_claim (username)
res = client.group.get_group_by_claim(client.auth.get_token(), "username", "rwelande")
if res is not None:
    print(res)

# get_group
res = client.group.get_group(client.auth.get_token(), "https://auth.cern.ch/auth/realms/cern", "asdoiqwe")

if res is not None:
    print(res)

# has_member
res = client.group.has_member(client.auth.get_token(), "somegroup", "rwelande", "https://auth.cern.ch/auth/realms/cern")

if res is not None:
    print(res)

# get_members
res = client.group.get_members(client.auth.get_token(), "somegroup", "https://auth.cern.ch/auth/realms/cern")
if res is not None:
    print(res)

# find_groups
res = client.group.find_groups(client.auth.get_token(), "rwel")
if res is not None:
    print(res)
