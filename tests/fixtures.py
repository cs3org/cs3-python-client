"""
fixtures.py

Contains the fixtures used in the tests.

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 30/08/2024

"""

import pytest
from unittest.mock import Mock, patch
from configparser import ConfigParser
import base64
import json

from cs3client.cs3client import CS3Client
from cs3client.file import File
from cs3client.auth import Auth
from cs3client.user import User
from cs3client.statuscodehandler import StatusCodeHandler
from cs3client.share import Share
from cs3client.app import App
from cs3client.checkpoint import Checkpoint
from cs3client.config import Config


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
    logger = Mock()
    logger.info = Mock()
    logger.error = Mock()
    logger.debug = Mock()
    logger.warning = Mock()
    return logger


@pytest.fixture
def mock_status_code_handler(mock_logger, mock_config):
    return StatusCodeHandler(mock_logger, Config(mock_config, "cs3client"))


# Here the order of patches correspond to the parameters of the function
@pytest.fixture
@patch("cs3.gateway.v1beta1.gateway_api_pb2_grpc.GatewayAPIStub")
def mock_gateway(mock_gateway_stub_class):
    mock_gateway_stub = Mock()
    mock_gateway_stub_class.return_value = mock_gateway_stub
    return mock_gateway_stub


# Here the order of patches correspond to the parameters of the function
# (patches are applied from the bottom up)
# and the last two parameters are inferred by pytest from existing fixtures
@pytest.fixture
@patch("cs3client.cs3client.grpc.secure_channel", autospec=True)
@patch("cs3client.cs3client.grpc.channel_ready_future", autospec=True)
@patch("cs3client.cs3client.grpc.insecure_channel", autospec=True)
@patch("cs3client.cs3client.cs3gw_grpc.GatewayAPIStub", autospec=True)
@patch("cs3client.cs3client.grpc.ssl_channel_credentials", autospec=True)
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

    assert mock_secure_channel.called
    assert mock_channel_ready_future.called
    assert mock_ssl_channel_credentials.called
    assert mock_insecure_channel.assert_not_called

    return client


# Here the order of patches correspond to the parameters of the function
# (patches are applied from the bottom up)
# and the last two parameters are inferred by pytest from existing fixtures
@pytest.fixture
@patch("cs3client.cs3client.grpc.secure_channel")
@patch("cs3client.cs3client.grpc.insecure_channel")
@patch("cs3client.cs3client.grpc.channel_ready_future")
@patch("cs3client.cs3client.cs3gw_grpc.GatewayAPIStub")
@patch("cs3client.cs3client.grpc.ssl_channel_credentials")
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

    assert mock_insecure_channel.called
    assert mock_channel_ready_future.called
    assert mock_secure_channel.assert_not_called
    assert mock_ssl_channel_credentials.assert_not_called
    return client


@pytest.fixture
def auth_instance(cs3_client_insecure):
    # Set up mock response for Authenticate method
    auth = Auth(cs3_client_insecure)
    auth.set_client_secret("test")
    return auth


# All the parameters are inferred by pytest from existing fixtures
@pytest.fixture
def app_instance(mock_gateway, mock_config, mock_logger, mock_status_code_handler):
    app = App(
        Config(mock_config, "cs3client"), mock_logger, mock_gateway, mock_status_code_handler
    )
    return app


@pytest.fixture
def checkpoint_instance(mock_gateway, mock_config, mock_logger, mock_status_code_handler):
    checkpoint = Checkpoint(
        Config(mock_config, "cs3client"), mock_logger, mock_gateway, mock_status_code_handler
    )
    return checkpoint


@pytest.fixture
def share_instance(mock_gateway, mock_config, mock_logger, mock_status_code_handler):
    share = Share(
        Config(mock_config, "cs3client"),
        mock_logger,
        mock_gateway,
        mock_status_code_handler,
    )
    return share


# All parameters are inferred by pytest from existing fixtures
@pytest.fixture
def file_instance(mock_gateway, mock_config, mock_logger, mock_status_code_handler):
    file = File(
        Config(mock_config, "cs3client"), mock_logger, mock_gateway, mock_status_code_handler
    )
    return file


@pytest.fixture
def user_instance(mock_gateway, mock_config, mock_logger, mock_status_code_handler):
    user = User(
        Config(mock_config, "cs3client"), mock_logger, mock_gateway, mock_status_code_handler
    )
    return user
