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
Last updated: 01/08/2024
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
client.auth.set_token("<your_token_here>")
# OR
# client.auth.set_client_secret("<your_client_secret_here>")

# Authentication
print(client.auth.get_token())

res = None

# mkdir
for i in range(1, 4):
    directory_resource = Resource.from_file_ref_and_endpoint(f"/eos/user/r/rwelande/test_directory{i}")
    res = client.file.make_dir(directory_resource)
    if res is not None:
        print(res)

# touchfile
touch_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/touch_file.txt")
text_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/text_file.txt")
res = client.file.touch_file(touch_resource)
res = client.file.touch_file(text_resource)

if res is not None:
    print(res)

# setxattr
resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/text_file.txt")
res = client.file.set_xattr(resource, "iop.wopi.lastwritetime", str(1720696124))

if res is not None:
    print(res)

# rmxattr
res = client.file.remove_xattr(resource, "iop.wopi.lastwritetime")

if res is not None:
    print(res)

# stat
res = client.file.stat(text_resource)

if res is not None:
    print(res)

# removefile
res = client.file.remove_file(touch_resource)

if res is not None:
    print(res)

res = client.file.touch_file(touch_resource)

# rename
rename_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande/rename_file.txt")
res = client.file.rename_file(resource, rename_resource)

if res is not None:
    print(res)

# writefile
content = b"Hello World"
size = len(content)
res = client.file.write_file(rename_resource, content, size)

if res is not None:
    print(res)

# rmdir (same as deletefile)
res = client.file.remove_file(directory_resource)

if res is not None:
    print(res)

# listdir
list_directory_resource = Resource.from_file_ref_and_endpoint("/eos/user/r/rwelande")
res = client.file.list_dir(list_directory_resource)

first_item = next(res, None)
if first_item is not None:
    print(first_item)
    for item in res:
        print(item)
else:
    print("empty response")

# readfile
file_res = client.file.read_file(rename_resource)
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
