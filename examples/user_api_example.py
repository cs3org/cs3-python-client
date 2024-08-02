"""
user_api_example.py

Example script to demonstrate the usage of the CS3Client class.


Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 02/08/2024
"""

import logging
import configparser
from cs3client import CS3Client

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

# find_user
res = client.user.find_users("rwel")
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
