"""
statuscodehandler.py

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 19/08/2024
"""

from exceptions.exceptions import AuthenticationException, NotFoundException, \
    UnknownException, AlreadyExistsException, FileLockedException
import logging
from config import Config
import cs3.rpc.v1beta1.code_pb2 as cs3code


class StatusCodeHandler:
    def __init__(self, log: logging.Logger, config: Config) -> None:
        self._log = log
        self._config = config

    # Note that res is of type any because it can be different types of respones
    # depending on the method that calls this function, I do not think importing
    # all the possible response types is a good idea
    def _log_not_found_info(self, status: any, operation: str, msg: str = None) -> None:
        self._log.info(
            f'msg="Not found on {operation}" {msg + " " if msg else ""}'
            f'userid="{self._config.auth_client_id}" trace="{status.trace}" '
            f'reason="{status.message.replace('"', "'")}"'
        )

    def _log_authentication_error(self, status: any, operation: str, msg: str = None) -> None:
        self._log.error(
            f'msg="Authentication failed on {operation}" {msg + " " if msg else ""}'
            f'userid="{self._config.auth_client_id}" trace="{status.trace}" '
            f'reason="{status.message.replace('"', "'")}"'
        )

    def _log_unknown_error(self, status: any, operation: str, msg: str = None) -> None:
        self._log.error(
            f'msg="Failed to {operation}, unknown error" {msg + " " if msg else ""}'
            f'userid="{self._config.auth_client_id}" trace="{status.trace}" '
            f'reason="{status.message.replace('"', "'")}"'
        )

    def _log_precondition_info(self, status: any, operation: str, msg: str = None) -> None:
        self._log.info(
            f'msg="Failed precondition on {operation}" {msg + " " if msg else ""}'
            f'userid="{self._config.auth_client_id}" trace="{status.trace}" '
            f'reason="{status.message.replace('"', "'")}"'
        )

    def _log_already_exists(self, status: any, operation: str, msg: str = None) -> None:
        self._log.info(
            f'msg="Already exists on {operation}" '
            f'userid="{self._config.auth_client_id}" trace="{status.trace}" '
            f'reason="{status.message.replace('"', "'")}"'
        )

    def handle_errors(self, status: any, operation: str, msg: str = None) -> None:
        if status.code == cs3code.CODE_OK:
            return
        if status.code == cs3code.CODE_FAILED_PRECONDITION or status.code == cs3code.CODE_ABORTED:
            self._log_precondition_info(status, operation, msg)
            raise FileLockedException(f'Failed precondition: '
                                      f'status_code="{status.code}"  message="{status.message}"')
        if status.code == cs3code.CODE_ALREADY_EXISTS:
            self._log_already_exists(status, operation, msg)
            raise AlreadyExistsException(f'Resource already exists: '
                                         f'status_code="{status.code}"  message="{status.message}"')
        if status.code == cs3code.CODE_NOT_FOUND:
            self._log_not_found_info(status, operation, msg)
            raise NotFoundException(f'Not found on {operation}: '
                                    f'status_code="{status.code}"  message="{status.message}"')
        if status.code == cs3code.CODE_UNAUTHENTICATED:
            self._log_authentication_error(status, operation, msg)
            raise AuthenticationException(f'Operation not permitted: '
                                          f'status_code="{status.code}"  message="{status.message}"')
        if status.code != cs3code.CODE_OK:
            if "path not found" in str(status.message).lower():
                self._log.info(f'msg="Invoked {operation} on missing file" ')
                raise NotFoundException(
                    message=f'No such file or directory: '
                            f'status_code="{status.code}"  message="{status.message}"'
                )
            self._log_unknown_error(status, operation, msg)
            raise UnknownException(f'Unknown Error: status_code="{status.code}"  message="{status.message}"')