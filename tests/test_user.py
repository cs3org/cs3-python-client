"""
test_user.py

Tests that the User class methods work as expected.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 01/08/2024
"""

from exceptions.exceptions import (
    AuthenticationException,
    NotFoundException,
    UnknownException,
)
import cs3.rpc.v1beta1.code_pb2 as cs3code
from fixtures import (  # noqa: F401 (they are used, the framework is not detecting it)
    mock_config,
    mock_logger,
    mock_authentication,
    mock_gateway,
    user_instance,
)
from unittest.mock import Mock, patch
import pytest

# Test cases for the User class


def test_get_user(user_instance):  # noqa: F811 (not a redefinition)
    idp = "idp"
    opaque_id = "opaque_id"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK
    mock_response.user.id.idp = idp
    mock_response.user.id.opaque_id = opaque_id
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "GetUser", return_value=mock_response):
        result = user_instance.get_user(idp, opaque_id)
        assert result == mock_response.user


def test_get_user_not_found(user_instance):  # noqa: F811 (not a redefinition)
    idp = "idp"
    opaque_id = "opaque_id"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_NOT_FOUND
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "GetUser", return_value=mock_response):
        with pytest.raises(NotFoundException):
            user_instance.get_user(idp, opaque_id)


def test_get_user_unknown_error(user_instance):  # noqa: F811 (not a redefinition)
    idp = "idp"
    opaque_id = "opaque_id"
    mock_response = Mock()
    mock_response.status.code = -2
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "GetUser", return_value=mock_response):
        with pytest.raises(UnknownException):
            user_instance.get_user(idp, opaque_id)


def test_get_user_by_claim(user_instance):  # noqa: F811 (not a redefinition)
    claim = "claim"
    value = "value"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK
    mock_response.user.id.idp = "idp"
    mock_response.user.id.opaque_id = "opaque_id"

    with patch.object(user_instance._gateway, "GetUserByClaim", return_value=mock_response):
        result = user_instance.get_user_by_claim(claim, value)
        assert result == mock_response.user


def test_get_user_by_claim_not_found(user_instance):  # noqa: F811 (not a redefinition)
    claim = "claim"
    value = "value"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_NOT_FOUND
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "GetUserByClaim", return_value=mock_response):
        with pytest.raises(NotFoundException):
            user_instance.get_user_by_claim(claim, value)


def test_get_user_by_claim_unknown_error(user_instance):  # noqa: F811 (not a redefinition)
    claim = "claim"
    value = "value"
    mock_response = Mock()
    mock_response.status.code = -2
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "GetUserByClaim", return_value=mock_response):
        with pytest.raises(UnknownException):
            user_instance.get_user_by_claim(claim, value)


def test_get_user_groups(user_instance):  # noqa: F811 (not a redefinition)
    idp = "idp"
    opaque_id = "opaque_id"
    mock_response = Mock()
    mock_response.groups = ["group1", "group2"]
    mock_response.status.code = cs3code.CODE_OK

    with patch.object(user_instance._gateway, "GetUserGroups", return_value=mock_response):
        result = user_instance.get_user_groups(idp, opaque_id)
        assert result == mock_response.groups


def test_get_user_groups_not_found(user_instance):  # noqa: F811 (not a redefinition)
    idp = "idp"
    opaque_id = "opaque_id"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_NOT_FOUND
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "GetUserGroups", return_value=mock_response):
        with pytest.raises(NotFoundException):
            user_instance.get_user_groups(idp, opaque_id)


def test_get_user_groups_unknown_error(user_instance):  # noqa: F811 (not a redefinition)
    idp = "idp"
    opaque_id = "opaque_id"
    mock_response = Mock()
    mock_response.status.code = -2
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "GetUserGroups", return_value=mock_response):
        with pytest.raises(UnknownException):
            user_instance.get_user_groups(idp, opaque_id)


def test_find_users(user_instance):  # noqa: F811 (not a redefinition)
    filter = "filter"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK
    mock_response.users = [Mock(), Mock()]

    with patch.object(user_instance._gateway, "FindUsers", return_value=mock_response):
        result = user_instance.find_users(filter)
        assert result == mock_response.users


def test_find_users_not_found(user_instance):  # noqa: F811 (not a redefinition)
    filter = "filter"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_NOT_FOUND
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "FindUsers", return_value=mock_response):
        with pytest.raises(NotFoundException):
            user_instance.find_users(filter)


def test_find_users_authentication_failed(user_instance):  # noqa: F811 (not a redefinition)
    filter = "filter"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "FindUsers", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            user_instance.find_users(filter)


def test_find_users_unknown_error(user_instance):  # noqa: F811 (not a redefinition)
    filter = "filter"
    mock_response = Mock()
    mock_response.status.code = -2
    mock_response.status.message = "error"

    with patch.object(user_instance._gateway, "FindUsers", return_value=mock_response):
        with pytest.raises(UnknownException):
            user_instance.find_users(filter)
