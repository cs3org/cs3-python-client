"""
user.py

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 02/08/2024
"""

import logging
from auth import Auth
from config import Config
import cs3.identity.user.v1beta1.resources_pb2 as cs3iur
import cs3.identity.user.v1beta1.user_api_pb2 as cs3iu
import cs3.rpc.v1beta1.code_pb2 as cs3code
from cs3.gateway.v1beta1.gateway_api_pb2_grpc import GatewayAPIStub
from exceptions.exceptions import AuthenticationException, NotFoundException, UnknownException


class User:
    """
    User class to handle user related API calls with CS3 Gateway API.
    """

    def __init__(self, config: Config, log: logging.Logger, gateway: GatewayAPIStub, auth: Auth) -> None:
        """
        Initializes the User class with logger, auth, and gateway stub,

        :param log: Logger instance for logging.
        :param gateway: GatewayAPIStub instance for interacting with CS3 Gateway.
        :param auth: An instance of the auth class.
        """
        self._auth: Auth = auth
        self._log: logging.Logger = log
        self._gateway: GatewayAPIStub = gateway
        self._config: Config = config
    
    # Note that res is of type any because it can be different types of respones
    # depending on the method that calls this function, I do not think importing
    # all the possible response types is a good idea
    def _log_not_found_info(self, res: any, operation: str) -> None:
        self._log.info(
            f'msg="Not found on {operation}" '
            f'userid="{self._config.auth_client_id}" trace="{res.status.trace}" '
            f'reason="{res.status.message.replace('"', "'")}"'
        )

    def _log_authentication_error(self, res: any, operation: str) -> None:
        self._log.error(
            f'msg="Authentication failed on {operation}" '
            f'userid="{self._config.auth_client_id}" trace="{res.status.trace}" '
            f'reason="{res.status.message.replace('"', "'")}"'
        )

    def _log_unknown_error(self, res: any, operation: str) -> None:
        self._log.error(
            f'msg="Failed to {operation}, unknown error" '
            f'userid="{self._config.auth_client_id}" trace="{res.status.trace}" '
            f'reason="{res.status.message.replace('"', "'")}"'
        )

    def _handle_errors(self, res: any, operation: str) -> None:
        if res.status.code == cs3code.CODE_NOT_FOUND:
            self._log_not_found_info(res, operation)
            raise NotFoundException(f"User not found: {res.status.message}")
        if res.status.code == cs3code.CODE_UNAUTHENTICATED:
            self._log_authentication_error(res, operation)
            raise AuthenticationException(f"Operation not permitted:  {res.status.message}")
        if res.status.code != cs3code.CODE_OK:
            self._log_unknown_error(res, operation)
            raise UnknownException(f"Unknown error:  {res.status.message}")

    def get_user(self, idp, opaque_id) -> cs3iur.User:
        """
        Get the user information provided the idp and opaque_id.

        :param idp: Identity provider.
        :param opaque_id: Opaque user id.
        :return: User information.
                 May return NotFoundException (User not found),
                 AuthenticationException (Operation not permitted), or
                 UnknownException (Unknown error).
        """
        req = cs3iu.GetUserRequest(user_id=cs3iur.UserId(idp=idp, opaque_id=opaque_id), skip_fetching_user_groups=True)
        res = self._gateway.GetUser(request=req)
        self._handle_errors(res, "get user")
        self._log.debug(f'msg="Invoked GetUser" idp="{res.user.id.idp}" opaque_id="{res.user.id.opaque_id}"')
        return res.user

    def get_user_by_claim(self, claim, value) -> cs3iur.User:
        """
        Get the user information provided the claim and value.

        :param claim: Claim to search for.
        :param value: Value to search for.
        :return: User information.
                 May return NotFoundException (User not found),
                 AuthenticationException (Operation not permitted), or
                 UnknownException (Unknown error).
        """
        req = cs3iu.GetUserByClaimRequest(claim=claim, value=value, skip_fetching_user_groups=True)
        res = self._gateway.GetUserByClaim(request=req)
        self._handle_errors(res, "get user by claim")
        self._log.debug(f'msg="Invoked GetUser" idp="{res.user.id.idp}" opaque_id="{res.user.id.opaque_id}"')
        return res.user

    def get_user_groups(self, idp, opaque_id) -> list[str]:
        """
        Get the groups the user is a part of.

        :param idp: Identity provider.
        :param opaque_id: Opaque user id.
        :return: A list of the groups the user is part of.
                 May return NotFoundException (User not found),
                 AuthenticationException (Operation not permitted), or
                 UnknownException (Unknown error).
        """
        req = cs3iu.GetUserGroupsRequest(user_id=cs3iur.UserId(idp=idp, opaque_id=opaque_id))
        res = self._gateway.GetUserGroups(request=req)
        self._handle_errors(res, "get user groups")
        self._log.debug(f'msg="Invoked GetUserGroups" idp="{req.user_id.idp}" opaque_id="{req.user_id.opaque_id}"')
        return res.groups

    def find_users(self, filter) -> list[cs3iur.User]:
        """
        Find a user based on a filter.

        :param filter: Filter to search for.
        :return: a list of user(s).
                 May return NotFoundException (User not found),
                 AuthenticationException (Operation not permitted), or
                 UnknownException (Unknown error).
        """
        req = cs3iu.FindUsersRequest(filter=filter, skip_fetching_user_groups=True)
        res = self._gateway.FindUsers(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(res, "find users")
        self._log.debug(f'msg="Invoked FindUsers" filter="{filter}"')
        return res.users
