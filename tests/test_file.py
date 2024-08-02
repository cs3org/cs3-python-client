"""
test_file.py

Tests that the File class methods work as expected.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 26/07/2024
"""

from cs3resource import Resource
from exceptions.exceptions import (
    AuthenticationException,
    NotFoundException,
    FileLockedException,
    UnknownException,
)
import cs3.rpc.v1beta1.code_pb2 as cs3code
from fixtures import (  # noqa: F401 (they are used, the framework is not detecting it)
    mock_config,
    mock_logger,
    mock_authentication,
    mock_gateway,
    file_instance,
)
from unittest.mock import Mock, patch
import pytest


# Test cases for File class


def test_stat(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK
    mock_response.info = "resource_info"

    with patch.object(file_instance._gateway, "Stat", return_value=mock_response):
        result = file_instance.stat(resource)
        assert result == "resource_info"


def test_stat_not_found(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_NOT_FOUND
    mock_response.status.message = "Resource not found"

    with patch.object(file_instance._gateway, "Stat", return_value=mock_response):
        with pytest.raises(NotFoundException):
            file_instance.stat(resource)


def test_stat_unauthenticated(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "Authentication failed"

    with patch.object(file_instance._gateway, "Stat", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            file_instance.stat(resource)


def test_stat_unknown_error(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = "-1"
    mock_response.status.message = "Internal error"

    with patch.object(file_instance._gateway, "Stat", return_value=mock_response):
        with pytest.raises(UnknownException):
            file_instance.stat(resource)


def test_setxattr(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    value = "testvalue"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK

    with patch.object(file_instance._gateway, "SetArbitraryMetadata", return_value=mock_response):
        file_instance.set_xattr(resource, key, value)


def test_setxattr_failed_precondition(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    value = "testvalue"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_FAILED_PRECONDITION
    mock_response.status.message = "Failed precondition"

    with patch.object(file_instance._gateway, "SetArbitraryMetadata", return_value=mock_response):
        with pytest.raises(FileLockedException):
            file_instance.set_xattr(resource, key, value)


def test_setxattr_failed_aborted(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    value = "testvalue"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_ABORTED
    mock_response.status.message = "Failed precondition"

    with patch.object(file_instance._gateway, "SetArbitraryMetadata", return_value=mock_response):
        with pytest.raises(IOError):
            file_instance.set_xattr(resource, key, value)


def test_setxattr_failed_unauthorized(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    value = "testvalue"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "Failed to authenticate"

    with patch.object(file_instance._gateway, "SetArbitraryMetadata", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            file_instance.set_xattr(resource, key, value)


def test_rmxattr(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK

    with patch.object(file_instance._gateway, "UnsetArbitraryMetadata", return_value=mock_response):
        file_instance.remove_xattr(resource, key)


def test_rmxattr_failed_precondition(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_FAILED_PRECONDITION
    mock_response.status.message = "Failed precondition"

    with patch.object(file_instance._gateway, "UnsetArbitraryMetadata", return_value=mock_response):
        with pytest.raises(FileLockedException):
            file_instance.remove_xattr(resource, key)


def test_rmxattr_failed_aborted(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_ABORTED
    mock_response.status.message = "Failed aborted"

    with patch.object(file_instance._gateway, "UnsetArbitraryMetadata", return_value=mock_response):
        with pytest.raises(IOError):
            file_instance.remove_xattr(resource, key)


def test_rmxattr_failed_authentication(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "Authentication Failed"

    with patch.object(file_instance._gateway, "UnsetArbitraryMetadata", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            file_instance.remove_xattr(resource, key)


def test_rmxattr_failed_unknown(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    key = "testkey"
    mock_response = Mock()
    mock_response.status.code = "-1"
    mock_response.status.message = "Failed aborted"

    with patch.object(file_instance._gateway, "UnsetArbitraryMetadata", return_value=mock_response):
        with pytest.raises(UnknownException):
            file_instance.remove_xattr(resource, key)


def test_rename_file(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    newresource = Resource.from_file_ref_and_endpoint(endpoint="", file="newtestfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK

    with patch.object(file_instance._gateway, "Move", return_value=mock_response):
        file_instance.rename_file(resource, newresource)


def test_rename_file_failed_precondition(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    newresource = Resource.from_file_ref_and_endpoint(endpoint="", file="newtestfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_FAILED_PRECONDITION
    mock_response.status.message = "Failed precondition"

    with patch.object(file_instance._gateway, "Move", return_value=mock_response):
        with pytest.raises(FileLockedException):
            file_instance.rename_file(resource, newresource)


def test_rename_file_failed_aborted(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    newresource = Resource.from_file_ref_and_endpoint(endpoint="", file="newtestfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_ABORTED
    mock_response.status.message = "Failed arborted"

    with patch.object(file_instance._gateway, "Move", return_value=mock_response):
        with pytest.raises(IOError):
            file_instance.rename_file(resource, newresource)


def test_rename_file_not_found(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    newresource = Resource.from_file_ref_and_endpoint(endpoint="", file="newtestfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_NOT_FOUND
    mock_response.status.message = "Failed not found"

    with patch.object(file_instance._gateway, "Move", return_value=mock_response):
        with pytest.raises(IOError):
            file_instance.rename_file(resource, newresource)


def test_rename_file_unuathorized(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    newresource = Resource.from_file_ref_and_endpoint(endpoint="", file="newtestfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "Failed to authenticate"

    with patch.object(file_instance._gateway, "Move", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            file_instance.rename_file(resource, newresource)


def test_rename_file_unknown_error(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    newresource = Resource.from_file_ref_and_endpoint(endpoint="", file="newtestfile")
    mock_response = Mock()
    mock_response.status.code = "-1"
    mock_response.status.message = "unknown error"

    with patch.object(file_instance._gateway, "Move", return_value=mock_response):
        with pytest.raises(UnknownException):
            file_instance.rename_file(resource, newresource)


def test_removefile(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK

    with patch.object(file_instance._gateway, "Delete", return_value=mock_response):
        file_instance.remove_file(resource)


def test_removefile_not_found(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_NOT_FOUND
    mock_response.status.message = "path not found"

    with patch.object(file_instance._gateway, "Delete", return_value=mock_response):
        with pytest.raises(IOError):
            file_instance.remove_file(resource)


def test_removefile_unauthorized(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "Failed to authenticate"

    with patch.object(file_instance._gateway, "Delete", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            file_instance.remove_file(resource)


def test_removefile_unknown_error(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = "-1"
    mock_response.status.message = "Unknown error"

    with patch.object(file_instance._gateway, "Delete", return_value=mock_response):
        with pytest.raises(UnknownException):
            file_instance.remove_file(resource)


def test_touchfile(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK

    with patch.object(file_instance._gateway, "TouchFile", return_value=mock_response):
        file_instance.touch_file(resource)


def test_touchfile_failed_precondition(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_FAILED_PRECONDITION
    mock_response.status.message = "Failed precondition"

    with patch.object(file_instance._gateway, "TouchFile", return_value=mock_response):
        with pytest.raises(FileLockedException):
            file_instance.touch_file(resource)


def test_touchfile_failed_unauthenticated(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "Failed to authenticate"

    with patch.object(file_instance._gateway, "TouchFile", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            file_instance.touch_file(resource)


def test_touchfile_unknown_error(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_response = Mock()
    mock_response.status.code = "-1"
    mock_response.status.message = "Unknown error"

    with patch.object(file_instance._gateway, "TouchFile", return_value=mock_response):
        with pytest.raises(UnknownException):
            file_instance.touch_file(resource)


def test_writefile(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    content = "testcontent"
    size = len(content)
    mock_upload_response = Mock()
    mock_upload_response.status.code = cs3code.CODE_OK
    mock_upload_response.protocols = [Mock(protocol="simple", upload_endpoint="http://example.com", token="token")]
    mock_put_response = Mock()
    mock_put_response.status_code = 200

    with patch.object(file_instance._gateway, "InitiateFileUpload", return_value=mock_upload_response):
        with patch("requests.put", return_value=mock_put_response):
            file_instance.write_file(resource, content, size)


def test_writefile_failed_precondition(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    content = "testcontent"
    size = len(content)
    mock_upload_response = Mock()
    mock_upload_response.status.code = cs3code.CODE_FAILED_PRECONDITION
    mock_upload_response.status.message = "Failed precondition"

    with patch.object(file_instance._gateway, "InitiateFileUpload", return_value=mock_upload_response):
        with pytest.raises(FileLockedException):
            file_instance.write_file(resource, content, size)


def test_writefile_failed_unauthenticated(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    content = "testcontent"
    size = len(content)
    mock_upload_response = Mock()
    mock_upload_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_upload_response.status.message = "Failed to authenticate"

    with patch.object(file_instance._gateway, "InitiateFileUpload", return_value=mock_upload_response):
        with pytest.raises(AuthenticationException):
            file_instance.write_file(resource, content, size)


def test_writefile_unknown_error(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    content = "testcontent"
    size = len(content)
    mock_upload_response = Mock()
    mock_upload_response.status.code = "-1"
    mock_upload_response.status.message = "Unknown error"

    with patch.object(file_instance._gateway, "InitiateFileUpload", return_value=mock_upload_response):
        with pytest.raises(UnknownException):
            file_instance.write_file(resource, content, size)


def test_make_dir(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testdir")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK

    with patch.object(file_instance._gateway, "CreateContainer", return_value=mock_response):
        file_instance.make_dir(resource)


def test_make_dir_failed_precondition(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testdir")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_FAILED_PRECONDITION
    mock_response.status.message = "Failed precondition"

    with patch.object(file_instance._gateway, "CreateContainer", return_value=mock_response):
        with pytest.raises(FileLockedException):
            file_instance.make_dir(resource)


def test_make_dir_failed_unauthenticated(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testdir")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "Failed to authenticate"

    with patch.object(file_instance._gateway, "CreateContainer", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            file_instance.make_dir(resource)


def test_make_dir_unknown_error(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testdir")
    mock_response = Mock()
    mock_response.status.code = "-1"
    mock_response.status.message = "Unknown error"

    with patch.object(file_instance._gateway, "CreateContainer", return_value=mock_response):
        with pytest.raises(UnknownException):
            file_instance.make_dir(resource)


def test_list_dir(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testdir")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_OK
    mock_response.infos = ["file1", "file2"]

    with patch.object(file_instance._gateway, "ListContainer", return_value=mock_response):
        res = file_instance.list_dir(resource)
        # Lazy evaluation
        first_item = next(res, None)
        if first_item is not None:
            for _ in res:
                pass


def test_list_dir_not_found(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testdir")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_NOT_FOUND
    mock_response.status.message = "Failed precondition"

    with patch.object(file_instance._gateway, "ListContainer", return_value=mock_response):
        with pytest.raises(NotFoundException):
            res = file_instance.list_dir(resource)
            # Lazy evaluation
            first_item = next(res, None)
            if first_item is not None:
                for _ in res:
                    pass


def test_list_dir_unauthenticated(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testdir")
    mock_response = Mock()
    mock_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_response.status.message = "Failed to authenticate"

    with patch.object(file_instance._gateway, "ListContainer", return_value=mock_response):
        with pytest.raises(AuthenticationException):
            res = file_instance.list_dir(resource)
            # Lazy evaluation
            first_item = next(res, None)
            if first_item is not None:
                for _ in res:
                    pass


def test_list_dir_unknown_error(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testdir")
    mock_response = Mock()
    mock_response.status.code = "-1"
    mock_response.status.message = "Unknown error"

    with patch.object(file_instance._gateway, "ListContainer", return_value=mock_response):
        with pytest.raises(UnknownException):
            res = file_instance.list_dir(resource)
            # Lazy evaluation
            first_item = next(res, None)
            if first_item is not None:
                for _ in res:
                    pass


def test_readfile_success(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_download_response = Mock()
    mock_download_response.status.code = cs3code.CODE_OK
    mock_download_response.protocols = [Mock(protocol="simple", download_endpoint="http://example.com", token="token")]

    mock_fileget_response = Mock()
    mock_fileget_response.status_code = 200
    mock_fileget_response.iter_content = Mock(return_value=[b"chunk1", b"chunk2"])

    with patch.object(
        file_instance._gateway,
        "InitiateFileDownload",
        return_value=mock_download_response,
    ):
        with patch("requests.get", return_value=mock_fileget_response):
            chunks = list(file_instance.read_file(resource))
            assert chunks == [b"chunk1", b"chunk2"]


def test_readfile_not_found(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_fileget_response = Mock()
    mock_fileget_response.status.code = cs3code.CODE_NOT_FOUND
    mock_fileget_response.iter_content = Mock(return_value="None")
    mock_fileget_response.status.message = "File not found"

    with patch.object(
        file_instance._gateway,
        "InitiateFileDownload",
        return_value=mock_fileget_response,
    ):
        with pytest.raises(NotFoundException):
            res = file_instance.read_file(resource)
            # Lazy evaluation
            first_item = next(res, None)
            if first_item is not None:
                for _ in res:
                    pass


def test_readfile_unauthenticated(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_fileget_response = Mock()
    mock_fileget_response.status.code = cs3code.CODE_UNAUTHENTICATED
    mock_fileget_response.status.message = "Failed to authenticate"

    with patch.object(
        file_instance._gateway,
        "InitiateFileDownload",
        return_value=mock_fileget_response,
    ):
        with pytest.raises(AuthenticationException):
            res = file_instance.read_file(resource)
            # Lazy evaluation
            first_item = next(res, None)
            if first_item is not None:
                for _ in res:
                    pass


def test_readfile_unknown_error(file_instance):  # noqa: F811 (not a redefinition)
    resource = Resource.from_file_ref_and_endpoint(endpoint="", file="testfile")
    mock_fileget_response = Mock()
    mock_fileget_response.status.code = "-1"
    mock_fileget_response.status.message = "Unknown error"

    with patch.object(
        file_instance._gateway,
        "InitiateFileDownload",
        return_value=mock_fileget_response,
    ):
        with pytest.raises(UnknownException):
            res = file_instance.read_file(resource)
            # Lazy evaluation
            first_item = next(res, None)
            if first_item is not None:
                for _ in res:
                    pass
