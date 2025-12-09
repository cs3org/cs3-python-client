"""
test_user.py

Tests that the User class methods work as expected.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 28/08/2024
"""

import pytest
from unittest.mock import Mock, patch
import cs3.rpc.v1beta1.code_pb2 as cs3code
import cs3.identity.user.v1beta1.user_api_pb2 as cs3iu
import cs3.identity.user.v1beta1.resources_pb2 as cs3iur
from cs3client.user import User


from cs3client.exceptions import (
    AuthenticationException,
    NotFoundException,
    UnknownException,
)
from .fixtures import (  # noqa: F401 (they are used, the framework is not detecting it)
    mock_config,
    mock_logger,
    mock_gateway,
    user_instance,
    mock_status_code_handler,
)

# Test cases for the User class


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, user_data",
    [
        (cs3code.CODE_OK, None, None, Mock(idp="idp", opaque_id="opaque_id")),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_get_user(
    user_instance, status_code, status_message, expected_exception, user_data  # noqa: F811 (not a redefinition)
):
    idp = "idp"
    opaque_id = "opaque_id"

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.user = user_data

    with patch.object(user_instance._gateway, "GetUser", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                user_instance.get_user(idp, opaque_id)
        else:
            result = user_instance.get_user(idp, opaque_id)
            assert result == user_data


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, user_data",
    [
        (cs3code.CODE_OK, None, None, Mock(idp="idp", opaque_id="opaque_id")),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_get_user_by_claim(
    user_instance, status_code, status_message, expected_exception, user_data  # noqa: F811 (not a redefinition)
):
    claim = "claim"
    value = "value"

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.user = user_data

    with patch.object(user_instance._gateway, "GetUserByClaim", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                user_instance.get_user_by_claim(claim, value)
        else:
            result = user_instance.get_user_by_claim(claim, value)
            assert result == user_data


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, groups",
    [
        (cs3code.CODE_OK, None, None, ["group1", "group2"]),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_get_user_groups(
    user_instance, status_code, status_message, expected_exception, groups  # noqa: F811 (not a redefinition)
):
    idp = "idp"
    opaque_id = "opaque_id"

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.groups = groups

    with patch.object(user_instance._gateway, "GetUserGroups", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                user_instance.get_user_groups(idp, opaque_id)
        else:
            result = user_instance.get_user_groups(idp, opaque_id)
            assert result == groups


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, users",
    [
        (cs3code.CODE_OK, None, None, [Mock(), Mock()]),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (cs3code.CODE_UNAUTHENTICATED, "error", AuthenticationException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_find_users(
    user_instance, status_code, status_message, expected_exception, users  # noqa: F811 (not a redefinition)
):
    filters = [
        cs3iu.Filter(
            type=cs3iur.UserType.USER_TYPE_PRIMARY
        )
    ]

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.users = users
    auth_token = ('x-access-token', "some_token")

    with patch.object(user_instance._gateway, "FindUsers", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                user_instance.find_users(auth_token, filters)
        else:
            result = user_instance.find_users(auth_token, filters)
            assert result == users


@pytest.mark.parametrize(
    "filter_type, query, user_type, expected_exception",
    [
        ("TYPE_QUERY", "test_user", None, None),
        ("TYPE_USERTYPE", None, "USER_TYPE_PRIMARY", None),
        ("TYPE_USERTYPE", None, "USER_TYPE_SECONDARY", None),
        ("TYPE_USERTYPE", None, "USER_TYPE_SERVICE", None),
        ("TYPE_USERTYPE", None, "USER_TYPE_GUEST", None),
        ("TYPE_USERTYPE", None, "USER_TYPE_FEDERATED", None),
        ("TYPE_USERTYPE", None, "USER_TYPE_LIGHTWEIGHT", None),
        ("TYPE_USERTYPE", None, "USER_TYPE_SPACE_OWNER", None),
        ("TYPE_USERTYPE", None, None, ValueError),
        ("TYPE_INVALID", "test", None, ValueError),
    ],
)
def test_create_find_user_filter(filter_type, query, user_type, expected_exception):
    """Test the create_find_user_filter classmethod."""

    if expected_exception:
        with pytest.raises(expected_exception):
            User.create_find_user_filter(filter_type, query, user_type)
    else:
        result = User.create_find_user_filter(filter_type, query, user_type)
        assert result is not None
        assert isinstance(result, cs3iu.Filter)


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, users, filter_type, query, user_type",
    [
        (cs3code.CODE_OK, None, None, [Mock(), Mock()], "TYPE_QUERY", "test_user", None),
        (cs3code.CODE_OK, None, None, [Mock()], "TYPE_USERTYPE", None, "USER_TYPE_PRIMARY"),
        (cs3code.CODE_OK, None, None, [Mock()], "TYPE_USERTYPE", None, "USER_TYPE_FEDERATED"),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None, "TYPE_QUERY", "nonexistent", None),
        (cs3code.CODE_UNAUTHENTICATED, "error", AuthenticationException, None, "TYPE_QUERY", "test", None),
        (-2, "error", UnknownException, None, "TYPE_USERTYPE", None, "USER_TYPE_SERVICE"),
    ],
)
def test_find_users_with_filter_creation(
    user_instance, status_code, status_message, expected_exception, users, filter_type, query, user_type  # noqa: F811 (not a redefinition)
):
    """Test find_users using the create_find_user_filter classmethod."""

    # Create filter using the classmethod
    user_filter = User.create_find_user_filter(filter_type, query, user_type)
    filters = [user_filter]

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.users = users
    auth_token = ('x-access-token', "some_token")

    with patch.object(user_instance._gateway, "FindUsers", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                user_instance.find_users(auth_token, filters)
        else:
            result = user_instance.find_users(auth_token, filters)
            assert result == users


@pytest.mark.parametrize(
    "status_code, status_message, expected_exception, users",
    [
        (cs3code.CODE_OK, None, None, [Mock(), Mock()]),
        (cs3code.CODE_NOT_FOUND, "error", NotFoundException, None),
        (cs3code.CODE_UNAUTHENTICATED, "error", AuthenticationException, None),
        (-2, "error", UnknownException, None),
    ],
)
def test_find_users_with_multiple_filters(
    user_instance, status_code, status_message, expected_exception, users  # noqa: F811 (not a redefinition)
):
    """Test find_users with multiple filters using the create_find_user_filter classmethod."""

    # Create multiple filters using the classmethod
    filter1 = User.create_find_user_filter("TYPE_QUERY", "test", None)
    filter2 = User.create_find_user_filter("TYPE_USERTYPE", None, "USER_TYPE_PRIMARY")
    filters = [filter1, filter2]

    mock_response = Mock()
    mock_response.status.code = status_code
    mock_response.status.message = status_message
    mock_response.users = users
    auth_token = ('x-access-token', "some_token")

    with patch.object(user_instance._gateway, "FindUsers", return_value=mock_response):
        if expected_exception:
            with pytest.raises(expected_exception):
                user_instance.find_users(auth_token, filters)
        else:
            result = user_instance.find_users(auth_token, filters)
            assert result == users
