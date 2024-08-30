"""
file_api_example.py

Example script to demonstrate the usage of the CS3Client class.
Start with an empty directory and you should end up with a directory structure like this:

test_directory1
test_directory2
test_directory3
rename_file.txt (containing "Hello World")
text_file.txt


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

# mkdir
for i in range(1, 4):
    directory_resource = Resource.from_file_ref_and_endpoint(f"/eos/user/r/rwelande/test_directory{i}")
    res = client.file.make_dir(auth.get_token(), directory_resource)
    if res is not None:
        print(res)

# touchfile
touch_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/touch_file.txt")
text_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/text_file.txt")
res = client.file.touch_file(auth.get_token(), touch_resource)
res = client.file.touch_file(auth.get_token(), text_resource)

if res is not None:
    print(res)

# setxattr
resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/text_file.txt")
res = client.file.set_xattr(auth.get_token(), resource, "iop.wopi.lastwritetime", str(1720696124))

if res is not None:
    print(res)

# rmxattr
res = client.file.remove_xattr(auth.get_token(), resource, "iop.wopi.lastwritetime")

if res is not None:
    print(res)

# stat
res = client.file.stat(auth.get_token(), text_resource)

if res is not None:
    print(res)

# removefile
res = client.file.remove_file(auth.get_token(), touch_resource)

if res is not None:
    print(res)

res = client.file.touch_file(auth.get_token(), touch_resource)

# rename
rename_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/rename_file.txt")
res = client.file.rename_file(auth.get_token(), resource, rename_resource)

if res is not None:
    print(res)

# writefile
content = b"Hello World"
size = len(content)
res = client.file.write_file(auth.get_token(), rename_resource, content, size)

if res is not None:
    print(res)

# rmdir (same as deletefile)
res = client.file.remove_file(auth.get_token(), directory_resource)

if res is not None:
    print(res)

# listdir
list_directory_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande")
res = client.file.list_dir(auth.get_token(), list_directory_resource)

first_item = next(res, None)
if first_item is not None:
    print(first_item)
    for item in res:
        print(item)
else:
    print("empty response")

# readfile
file_res = client.file.read_file(auth.get_token(), rename_resource)
content = b""
try:
    for chunk in file_res:
        if isinstance(chunk, Exception):
            raise chunk
        content += chunk
    print(content.decode("utf-8"))
except Exception as e:
    print(f"An error occurred: {e}")
    print(e)
