"""
fixtures.py

Contains the fixtures used in the tests.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 26/07/2024

"""

import pytest
from unittest.mock import Mock, patch
from configparser import ConfigParser
import cs3.rpc.v1beta1.code_pb2 as cs3code
from cs3client import CS3Client
from file import File
from auth import Auth
from user import User
from config import Config
import base64
import json


@pytest.fixture
def mock_config():
    config = ConfigParser()
    config["cs3client"] = {
        # client parameters
        "host": "test_host:port",
        "grpc_timeout": "10",
        "chunk_size": "4194304",
        "http_timeout": "10",
        # TUS parameters
        "tus_enabled": "False",
        # Authentication parameters
        "auth_login_type": "basic",
        "auth_client_id": "einstein",
        # SSL parameters
        "ssl_enabled": "True",
        "ssl_verify": "True",
        "ssl_ca_cert": "test_ca_cert",
        "ssl_client_key": "test_client_key",
        "ssl_client_cert": "test_client_cert",
        # Lock parameters
        "lock_not_impl": "False",
        "lock_by_setting_attr": "False",
        "lock_expiration": "1800",
    }
    return config


def create_mock_jwt():
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().strip("=")
    payload = (
        base64.urlsafe_b64encode(json.dumps({"sub": "1234567890", "name": "John Doe", "iat": 1516239022}).encode())
        .decode()
        .strip("=")
    )
    signature = base64.urlsafe_b64encode(b"signature").decode().strip("=")
    return f"{header}.{payload}.{signature}"


@pytest.fixture
def mock_logger():
    return Mock()


# Here the order of patches correspond to the parameters of the function
@pytest.fixture
@patch("cs3.gateway.v1beta1.gateway_api_pb2_grpc.GatewayAPIStub")
def mock_gateway(mock_gateway_stub_class):
    mock_gateway_stub = Mock()
    mock_gateway_stub_class.return_value = mock_gateway_stub
    # Set up mock response for Authenticate method
    mocked_token = create_mock_jwt()
    mock_authenticate_response = Mock()
    mock_authenticate_response.status.code = cs3code.CODE_OK
    mock_authenticate_response.status.message = ""
    mock_authenticate_response.token = mocked_token
    mock_gateway_stub.Authenticate.return_value = mock_authenticate_response
    return mock_gateway_stub


# All the parameters are inferred by pytest from existing fixtures
@pytest.fixture
def mock_authentication(mock_gateway, mock_config, mock_logger):
    # Set up mock response for Authenticate method
    mock_authentication = Auth(Config(mock_config, "cs3client"), mock_logger, mock_gateway)
    mock_authentication.set_client_secret("test")
    return mock_authentication


# Here the order of patches correspond to the parameters of the function
# (patches are applied from the bottom up)
# and the last two parameters are inferred by pytest from existing fixtures
@pytest.fixture
@patch("cs3client.grpc.secure_channel", autospec=True)
@patch("cs3client.grpc.channel_ready_future", autospec=True)
@patch("cs3client.grpc.insecure_channel", autospec=True)
@patch("cs3client.cs3gw_grpc.GatewayAPIStub", autospec=True)
@patch("cs3client.grpc.ssl_channel_credentials", autospec=True)
def cs3_client_secure(
    mock_ssl_channel_credentials,
    mock_gateway_stub_class,
    mock_insecure_channel,
    mock_channel_ready_future,
    mock_secure_channel,
    mock_config,
    mock_logger,
):

    # Create CS3Client instance
    client = CS3Client(mock_config, "cs3client", mock_logger)
    client.auth.set_client_secret("test")

    assert mock_secure_channel.called
    assert mock_channel_ready_future.called
    assert mock_ssl_channel_credentials.called
    assert mock_insecure_channel.assert_not_called

    return client


# Here the order of patches correspond to the parameters of the function
# (patches are applied from the bottom up)
# and the last two parameters are inferred by pytest from existing fixtures
@pytest.fixture
@patch("cs3client.grpc.secure_channel")
@patch("cs3client.grpc.insecure_channel")
@patch("cs3client.grpc.channel_ready_future")
@patch("cs3client.cs3gw_grpc.GatewayAPIStub")
@patch("cs3client.grpc.ssl_channel_credentials")
def cs3_client_insecure(
    mock_ssl_channel_credentials,
    mock_gateway_stub_class,
    mock_channel_ready_future,
    mock_insecure_channel,
    mock_secure_channel,
    mock_config,
    mock_logger,
):
    mock_config["cs3client"]["ssl_enabled"] = "False"

    # Create CS3Client instance
    client = CS3Client(mock_config, "cs3client", mock_logger)
    client.auth.set_client_secret("test")

    assert mock_insecure_channel.called
    assert mock_channel_ready_future.called
    assert mock_secure_channel.assert_not_called
    assert mock_ssl_channel_credentials.assert_not_called
    return client


# All parameters are inferred by pytest from existing fixtures
@pytest.fixture
def file_instance(mock_authentication, mock_gateway, mock_config, mock_logger):
    file = File(Config(mock_config, "cs3client"), mock_logger, mock_gateway, mock_authentication)
    return file


@pytest.fixture
def user_instance(mock_authentication, mock_gateway, mock_config, mock_logger):
    user = User(Config(mock_config, "cs3client"), mock_logger, mock_gateway, mock_authentication)
    return user
