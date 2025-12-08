"""
group.py

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 08/12/2025
"""

import logging
import cs3.identity.group.v1beta1.resources_pb2 as cs3igr
import cs3.identity.group.v1beta1.group_api_pb2 as cs3ig
import cs3.identity.user.v1beta1.resources_pb2 as cs3iur
from cs3.gateway.v1beta1.gateway_api_pb2_grpc import GatewayAPIStub

from .config import Config
from .statuscodehandler import StatusCodeHandler


class Group:
    """
    Group class to handle group related API calls with CS3 Gateway API.
    """

    def __init__(
        self,
        config: Config,
        log: logging.Logger,
        gateway: GatewayAPIStub,
        status_code_handler: StatusCodeHandler,
    ) -> None:
        """
        Initializes the Group class with logger, auth, and gateway stub,

        :param log: Logger instance for logging.
        :param gateway: GatewayAPIStub instance for interacting with CS3 Gateway.
        :param auth: An instance of the auth class.
        """
        self._log: logging.Logger = log
        self._gateway: GatewayAPIStub = gateway
        self._config: Config = config
        self._status_code_handler: StatusCodeHandler = status_code_handler

    def get_group(self, auth_token: tuple, opaque_id, idp) -> cs3igr.Group:
        """
        Get the group information provided the opaque_id.

        :param opaque_id: Opaque group id.
        :return: Group information.
        :raises: return NotFoundException (Group not found)
        :raises: AuthenticationException (Operation not permitted)
        :raises: UnknownException (Unknown error)
        """
        req = cs3ig.GetGroupRequest(group_id=cs3igr.GroupId(opaque_id=opaque_id, idp=idp))
        res = self._gateway.GetGroup(request=req, metadata=[auth_token])
        self._status_code_handler.handle_errors(res.status, "get group", f'opaque_id="{opaque_id}"')
        self._log.debug(f'msg="Invoked GetGroup" opaque_id="{res.group.id.opaque_id}" trace="{res.status.trace}"')
        return res.group

    def get_group_by_claim(self, auth_token: tuple, claim, value) -> cs3igr.Group:
        """
        Get the group information provided the claim and value.

        :param claim: Claim to search for.
        :param value: Value to search for.
        :return: Group information.
        :raises: NotFoundException (Group not found)
        :raises: AuthenticationException (Operation not permitted)
        :raises: UnknownException (Unknown error)
        """
        req = cs3ig.GetGroupByClaimRequest(claim=claim, value=value, skip_fetching_members=False)
        res = self._gateway.GetGroupByClaim(request=req, metadata=[auth_token])
        self._status_code_handler.handle_errors(res.status, "get group by claim", f'claim="{claim}" value="{value}"')
        self._log.debug(f'msg="Invoked GetGroupByClaim" opaque_id="{res.group.id.opaque_id}" trace="{res.status.trace}"')
        return res.group

    def has_member(self, auth_token: tuple, group_opaque_id, user_opaque_id, idp) -> bool:
        """
        Check if a user is a member of a group.

        :param group_opaque_id: Group opaque id.
        :param user_opaque_id: User opaque id.
        :return: True if the user is a member of the group, False otherwise.
        :raises: NotFoundException (Group not found)
        :raises: AuthenticationException (Operation not permitted)
        :raises: UnknownException (Unknown error)
        """
        req = cs3ig.HasMemberRequest(group_id=cs3igr.GroupId(opaque_id=group_opaque_id, idp=idp), user_id=cs3iur.UserId(opaque_id=user_opaque_id, idp=idp))
        res = self._gateway.HasMember(request=req, metadata=[auth_token])
        self._status_code_handler.handle_errors(res.status, "has member", f'group_id="{group_opaque_id}" user_id="{user_opaque_id}"')
        self._log.debug(f'msg="Invoked HasMember" group_id="{group_opaque_id}" user_id="{user_opaque_id}" trace="{res.status.trace}"')
        return res.ok

    def get_members(self, auth_token: tuple, opaque_id, idp) -> list[str]:
        """
        Get the groups the user is a part of.

        :param opaque_id: Opaque group id.
        :return: A list of the groups the user is part of.
        :raises: NotFoundException (User not found)
        :raises: AuthenticationException (Operation not permitted)
        :raises: UnknownException (Unknown error)
        """
        req = cs3ig.GetMembersRequest(group_id=cs3igr.GroupId(idp=idp, opaque_id=opaque_id))
        res = self._gateway.GetUserGroups(request=req, metadata=[auth_token])
        self._status_code_handler.handle_errors(res.status, "get user groups", f'opaque_id="{opaque_id}"')
        self._log.debug(f'msg="Invoked GetUserGroups" opaque_id="{opaque_id}" trace="{res.status.trace}"')
        return res.groups

    def find_groups(self, auth_token: tuple, filters) -> list[cs3igr.Group]:
        """
        Find a group based on a filter.

        :param auth_token: tuple in the form ('x-access-token', <token>) (see auth.get_token/auth.check_token)
        :param filters: Filters to search for.
        :return: a list of group(s).
        :raises: NotFoundException (Group not found)
        :raises: AuthenticationException (Operation not permitted)
        :raises: UnknownException (Unknown error)
        """
        req = cs3ig.FindGroupsRequest(filters=filters)
        res = self._gateway.FindGroups(request=req, metadata=[auth_token])
        self._status_code_handler.handle_errors(res.status, "find groups")
        self._log.debug(f'msg="Invoked FindGroups" filter="{filter}" trace="{res.status.trace}"')
        return res.groups
