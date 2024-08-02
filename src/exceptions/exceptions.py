"""
exceptions.py

Custom exception classes for the CS3 client.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 01/08/2024
"""


class AuthenticationException(Exception):
    """
    Standard error thrown when attempting an operation without the required access rights
    """

    def __init__(self, message: str = ""):
        super().__init__(message)


class NotFoundException(IOError):
    """
    Standard file missing message
    """

    def __init__(self, message: str = ""):
        super().__init__(message)


class SecretNotSetException(Exception):
    """
    Standard file missing message
    """

    def __init__(self, message: str = ""):
        super().__init__(message)


class FileLockedException(IOError):
    """
    Standard error thrown when attempting to overwrite a file/xattr or when
    a lock operation cannot be performed because of failed preconditions
    """

    def __init__(self, message: str = ""):
        super().__init__(message)


class UnknownException(Exception):
    """
    Standard exception to be thrown when we get an error that is unknown, e.g. not defined in the cs3api
    """

    def __init__(self, message: str = ""):
        super().__init__(message)
