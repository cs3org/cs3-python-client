"""
space.py

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 23/02/2026
"""

import logging
from typing import Literal
from cs3.gateway.v1beta1.gateway_api_pb2_grpc import GatewayAPIStub

from .config import Config
from .statuscodehandler import StatusCodeHandler
import cs3.storage.provider.v1beta1.spaces_api_pb2 as cs3spp
import cs3.storage.provider.v1beta1.resources_pb2 as cs3spr
import cs3.identity.user.v1beta1.resources_pb2 as cs3iur



class Space:
    """
    Space class to handle space related API calls with CS3 Gateway API.
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

    def list_storage_spaces(self, auth_token: tuple, filters) -> list[cs3spr.StorageSpace]:
        """
        Find a space based on a filter.

        :param auth_token: tuple in the form ('x-access-token', <token>) (see auth.get_token/auth.check_token)
        :param filters: Filters to search for.
        :return: a list of space(s).
        :raises: NotFoundException (Space not found)
        :raises: AuthenticationException (Operation not permitted)
        :raises: UnknownException (Unknown error)
        """
        req = cs3spp.ListStorageSpacesRequest(filters=filters)
        res = self._gateway.ListStorageSpaces(request=req, metadata=[auth_token])
        self._status_code_handler.handle_errors(res.status, "find storage spaces")
        self._log.debug(f'msg="Invoked FindStorageSpaces" filter="{filter}" trace="{res.status.trace}"')
        return res.storage_spaces

    @classmethod
    def create_storage_space_filter(cls, filter_type: Literal["TYPE_ID", "TYPE_OWNER", "TYPE_SPACE_TYPE", "TYPE_PATH", "TYPE_USER"], space_type: str = None, path: str = None, opaque_id: str = None, user_idp: str = None, user_type: str = None) -> cs3spp.ListStorageSpacesRequest.Filter:
        """
        Create a filter for listing storage spaces.

        :param filter_value: Value of the filter.
        :param filter_type: Type of the filter. Supported values are "TYPE_ID", "TYPE_OWNER", "TYPE_SPACE_TYPE",  "TYPE_PATH" and "TYPE_USER".
        :param space_type: Space type to filter by (required if filter_type is "SPACE_TYPE").
        :param path: Path to filter by (required if filter_type is "PATH").
        :param opaque_id: Opaque ID to filter by (required if filter_type is "ID").
        :param user_idp: User identity provider to filter by (required if filter_type is "OWNER" or "USER").
        :param user_type: User type to filter by (required if filter_type is "OWNER" or "USER").
        :param filter_value: Value of the filter.
        :return: A cs3spp.ListStorageSpacesRequest.Filter object.
        :raises: ValueError (Unsupported filter type)
        """
        try:
            if filter_type is None:
                raise ValueError(f'Unsupported filter type: {filter_type}. Supported values are "TYPE_ID", "TYPE_OWNER", "TYPE_SPACE_TYPE",  "TYPE_PATH" and "TYPE_USER".')
            filter_type_value = cs3spp.ListStorageSpacesRequest.Filter.Type.Value(filter_type)
            if space_type and filter_type == "TYPE_SPACE_TYPE":
                return cs3spp.ListStorageSpacesRequest.Filter(type=filter_type_value, space_type=space_type)
            if path and filter_type == "TYPE_PATH":
                return cs3spp.ListStorageSpacesRequest.Filter(type=filter_type_value, path=path)
            if user_idp and user_type and opaque_id and filter_type == "TYPE_OWNER":
                user_type = cs3iur.UserType.Value(user_type.upper())
                user_id = cs3iur.UserId(idp=user_idp, type=user_type, opaque_id=opaque_id)
                return cs3spp.ListStorageSpacesRequest.Filter(type=filter_type_value, owner=user_id)
            if user_idp and user_type and opaque_id and filter_type == "TYPE_USER":
                user_type = cs3iur.UserType.Value(user_type.upper())
                user_id = cs3iur.UserId(idp=user_idp, type=user_type, opaque_id=opaque_id)
                return cs3spp.ListStorageSpacesRequest.Filter(type=filter_type_value, user=user_id)
            if opaque_id and filter_type == "TYPE_ID":
                id = cs3spr.StorageSpaceId(opaque_id=opaque_id)
                return cs3spp.ListStorageSpacesRequest.Filter(type=filter_type_value, id=id)
        except ValueError as e:
            raise ValueError(f"Failed to create storage space filter: {e}")
        raise ValueError(f'Unsupported filter type: {filter_type}. Supported values are "TYPE_ID", "TYPE_OWNER", "TYPE_SPACE_TYPE",  "TYPE_PATH" and "TYPE_USER".')