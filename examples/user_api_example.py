"""
user_api_example.py

Example script to demonstrate the usage of the CS3Client class.


Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 30/08/2024
"""

import logging
import configparser
from cs3client import CS3Client
from auth import Auth

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

# find_user
res = client.user.find_users(client.auth.get_token(), "rwel")
if res is not None:
    print(res)

# get_user
res = client.user.get_user("https://auth.cern.ch/auth/realms/cern", "asdoiqwe")

if res is not None:
    print(res)

# get_user_groups
res = client.user.get_user_groups("https://auth.cern.ch/auth/realms/cern", "rwelande")

if res is not None:
    print(res)

# get_user_by_claim (mail)
res = client.user.get_user_by_claim("mail", "rasmus.oscar.welander@cern.ch")
if res is not None:
    print(res)

# get_user_by_claim (username)
res = client.user.get_user_by_claim("username", "rwelande")
if res is not None:
    print(res)
