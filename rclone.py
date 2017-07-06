# -*- coding: utf-8 -*-
"""
Manage VNC connection and hashing of password


"""

# Import python libs
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function


import array
import os
import getpass
import logging
import socket
import select
import random
import string
import time
import sys
import threading
import binascii
from struct import pack, unpack
import base64
import base32hex
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter


# Import 3rdp-party libs
from salt.ext.six.moves import range  # pylint: disable=import-error,redefined-builtin

# Import salt libs
import salt.utils
from salt.exceptions import CommandExecutionError, SaltInvocationError
from salt.ext import six
from salt.ext.six import string_types

logger = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'rclone'

# RClone Key
key = [156, 147, 91, 72, 115, 10, 85, 77, 107, 253, 124, 99, 200, 134, 169, 43, 211, 144, 25, 142, 184, 18, 138, 251, 244, 222, 22, 43, 139, 149, 246, 56]

def obscure(password):
    """Obscure a password to be store in the conf."""
    real_key = bytearray(key)
    # We dont care that the counter does not change. The key is public so ...
    counter = b'4242424242424242'
    cypher = AES.new(bytes(real_key), AES.MODE_CTR, counter=lambda: counter)
    encrypted = cypher.encrypt(password)
    return base64.urlsafe_b64encode(counter + encrypted).replace('=', '')

if __name__ == "__main__":
    print(obscure(str(sys.argv[1])))
