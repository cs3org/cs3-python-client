"""
exceptions.py

Custom exception classes for the CS3 client.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 29/07/2024
"""


class AuthenticationException(Exception):
    """
    Standard error thrown when attempting an operation without the required access rights
    """

    def __init__(self, message: str = ""):
        super().__init__("Operation not permitted" + " " + message)


class NotFoundException(IOError):
    """
    Standard file missing message
    """

    def __init__(self, message: str = ""):
        super().__init__("No such file or directory" + " " + message)


class SecretNotSetException(Exception):
    """
    Standard file missing message
    """

    def __init__(self, message: str = ""):
        super().__init__("The client secret (e.g. token, passowrd) is not set" + " " + message)


class FileLockedException(IOError):
    """
    Standard error thrown when attempting to overwrite a file/xattr in O_EXCL mode
    or when a lock operation cannot be performed because of failed preconditions
    """

    def __init__(self, message: str = ""):
        super().__init__("File/xattr exists but EXCL mode requested, lock mismatch or lock expired" + " " + message)


class UnknownException(Exception):
    """
    Standard exception to be thrown when we get an error that is unknown, e.g. not defined in the cs3api
    """

    def __init__(self, message: str = ""):
        super().__init__(message)
