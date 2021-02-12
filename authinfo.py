#!/usr/bin/env python

import base64

class ApiAuth(object):
    """ Providers auth information """

    def __init__(self, username, password=""):
        self._username = username
        self._password = password

    @property
    def username(self):
        if self._password != "":
            raise NotImplementedError
        return self._username

    @property
    def base64Key(self):
        auth_str = "%s:%s" % (self._username, self._password)
        return base64.b64encode(auth_str.encode('utf-8'))

    @classmethod
    def decodeKey(cls, encoded_key):
        """Return decoded key from an encoded key """

        auth_str = base64.b64decode(encoded_key).decode('utf-8')
        username, password = auth_str.strip().split(':', 1)

        instance = cls(username, password)
        return cls

    def __str__(self):
        return self.base64Key.decode('utf-8')

    def __eq__(self, other):
        return str(self) == str(other)


def decodeKey(encoded_key):
    """Return decoded key from an encoded key """
    auth_str = base64.b64decode(encoded_key).decode('utf-8')
    username, password = auth_str.strip().split(':', 1)
    return username.replace("'",""), password.replace("'","")
