"""
test_space.py

Tests that the Space class methods work as expected.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 23/02/2026
"""


import pytest
from unittest.mock import Mock, patch
import cs3.rpc.v1beta1.code_pb2 as cs3code
import cs3.storage.provider.v1beta1.spaces_api_pb2 as cs3spp
import cs3.identity.user.v1beta1.resources_pb2 as cs3iur
import cs3.storage.provider.v1beta1.resources_pb2 as cs3spr

from cs3client.exceptions import (
    AuthenticationException,
    UnknownException,
)
from .fixtures import (  # noqa: F401 (they are used, the framework is not detecting it)
    mock_config,
    mock_logger,
    mock_gateway,
    mock_status_code_handler,
)

@pytest.fixture
def space_instance(mock_config, mock_logger, mock_gateway, mock_status_code_handler):  # noqa: F811
    """
    Fixture for creating a Space instance with mocked dependencies.
    """
    from cs3client.space import Space

    return Space(mock_config, mock_logger, mock_gateway, mock_status_code_handler)


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception",
    [
        (cs3code.CODE_OK, None, None),
        (cs3code.CODE_UNAUTHENTICATED, "error", AuthenticationException),
        (cs3code.CODE_INTERNAL, "error", UnknownException),
    ],
)
def test_list_storage_spaces(space_instance, status_code, status_message, expected_exception):  # noqa: F811
    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.storage_spaces = ["space1", "space2"]
    auth_token = ('x-access-token', "some_token")

    with patch.object(space_instance._gateway, "ListStorageSpaces", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                space_instance.list_storage_spaces(auth_token, filters=[])
        else:
            result = space_instance.list_storage_spaces(auth_token, filters=[])
            assert result == ["space1", "space2"]

@pytest.mark.parametrize(
    "filter_type, space_type, path, opaque_id, user_idp, user_type, expected_filter",
    [
        ("TYPE_SPACE_TYPE", "home", None, None, None, None, cs3spp.ListStorageSpacesRequest.Filter(type="TYPE_SPACE_TYPE", space_type="home")),
        ("TYPE_PATH", None, "/path/to/space", None, None, None, cs3spp.ListStorageSpacesRequest.Filter(type="TYPE_PATH", path="/path/to/space")),
        ("TYPE_OWNER", None, None, "opaque_id", "user_idp", "USER_TYPE_PRIMARY", cs3spp.ListStorageSpacesRequest.Filter(type="TYPE_OWNER", owner=cs3iur.UserId(idp="user_idp", type=cs3iur.UserType.Value("USER_TYPE_PRIMARY"), opaque_id="opaque_id"))),
        ("TYPE_USER", None, None, "opaque_id", "user_idp", "USER_TYPE_PRIMARY", cs3spp.ListStorageSpacesRequest.Filter(type="TYPE_USER", user=cs3iur.UserId(idp="user_idp", type=cs3iur.UserType.Value("USER_TYPE_PRIMARY"), opaque_id="opaque_id"))),
        ("TYPE_ID", None, None, "opaque_id", None, None, cs3spp.ListStorageSpacesRequest.Filter(type="TYPE_ID", id=cs3spr.StorageSpaceId(opaque_id="opaque_id"))),
    ],
)
def test_create_storage_space_filter(space_instance, filter_type, space_type, path, opaque_id, user_idp, user_type, expected_filter):  # noqa: F811
    result = space_instance.create_storage_space_filter(filter_type, space_type, path, opaque_id, user_idp, user_type)
    assert result == expected_filter