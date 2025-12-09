"""
test_group.py

Tests that the Group class methods work as expected.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 08/12/2025
"""

import pytest
from unittest.mock import Mock, patch
import cs3.rpc.v1beta1.code_pb2 as cs3code
import cs3.identity.group.v1beta1.group_api_pb2 as cs3ig
import cs3.identity.group.v1beta1.resources_pb2 as cs3igr

from cs3client.exceptions import (
    AuthenticationException,
    NotFoundException,
    UnknownException,
)
from .fixtures import (  # noqa: F401 (they are used, the framework is not detecting it)
    mock_config,
    mock_logger,
    mock_gateway,
    mock_status_code_handler,
)


@pytest.fixture
def group_instance(mock_config, mock_logger, mock_gateway, mock_status_code_handler):  # noqa: F811
    """
    Fixture for creating a Group instance with mocked dependencies.
    """
    from cs3client.group import Group

    return Group(mock_config, mock_logger, mock_gateway, mock_status_code_handler)


# Test cases for the Group class


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, group_data",
    [
        (cs3code.CODE_OK, None, None, Mock(id=Mock(idp="idp", opaque_id="opaque_id"))),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_get_group(
    group_instance, status_code, status_message, expected_exception, group_data  # noqa: F811 (not a redefinition)
):
    idp = "idp"
    opaque_id = "opaque_id"

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.group = group_data
    auth_token = ('x-access-token', "some_token")


    with patch.object(group_instance._gateway, "GetGroup", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                group_instance.get_group(auth_token, opaque_id, idp)
        else:
            result = group_instance.get_group(auth_token, opaque_id, idp)
            assert result == group_data


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, has_member",
    [
        (cs3code.CODE_OK, None, None, True),
        (cs3code.CODE_OK, None, None, False),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_has_member(
    group_instance, status_code, status_message, expected_exception, has_member  # noqa: F811 (not a redefinition)
):
    group_opaque_id = "group_opaque_id"
    user_opaque_id = "user_opaque_id"
    user_idp = "user_idp"

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.ok = has_member
    auth_token = ('x-access-token', "some_token")


    with patch.object(group_instance._gateway, "HasMember", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                group_instance.has_member(auth_token, group_opaque_id, user_opaque_id, user_idp)
        else:
            result = group_instance.has_member(auth_token, group_opaque_id, user_opaque_id, user_idp)
            assert result == has_member


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, groups",
    [
        (cs3code.CODE_OK, None, None, ["member1", "member2"]),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_get_members(
    group_instance, status_code, status_message, expected_exception, groups  # noqa: F811 (not a redefinition)
):
    idp = "idp"
    opaque_id = "opaque_id"

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.groups = groups
    auth_token = ('x-access-token', "some_token")


    with patch.object(group_instance._gateway, "GetUserGroups", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                group_instance.get_members(auth_token, opaque_id, idp)
        else:
            result = group_instance.get_members(auth_token, opaque_id, idp)
            assert result == groups


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, groups",
    [
        (cs3code.CODE_OK, None, None, [Mock(), Mock()]),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (cs3code.CODE_UNAUTHENTICATED, "error", AuthenticationException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_find_groups(
    group_instance, status_code, status_message, expected_exception, groups  # noqa: F811 (not a redefinition)
):
    filters = [
        cs3ig.Filter(
            type=cs3igr.GroupType.GROUP_TYPE_FEDERATED,
        )
    ]

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.groups = groups
    auth_token = ('x-access-token', "some_token")

    with patch.object(group_instance._gateway, "FindGroups", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                group_instance.find_groups(auth_token, filters)
        else:
            result = group_instance.find_groups(auth_token, filters)
            assert result == groups



@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, group_data",
    [
        (cs3code.CODE_OK, None, None, Mock(idp="idp", opaque_id="opaque_id")),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_get_group_by_claim(
    group_instance, status_code, status_message, expected_exception, group_data  # noqa: F811 (not a redefinition)
):
    claim = "claim"
    value = "value"

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.group = group_data
    auth_token = ('x-access-token', "some_token")

    with patch.object(group_instance._gateway, "GetGroupByClaim", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                group_instance.get_group_by_claim(auth_token, claim, value)
        else:
            result = group_instance.get_group_by_claim(auth_token, claim, value)
            assert result == group_data