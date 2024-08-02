"""
auth.py

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 01/08/2024
"""

import grpc
import jwt
import datetime
import logging
import cs3.gateway.v1beta1.gateway_api_pb2 as gw
from cs3.auth.registry.v1beta1.registry_api_pb2 import ListAuthProvidersRequest
from cs3.gateway.v1beta1.gateway_api_pb2_grpc import GatewayAPIStub
from cs3.rpc.v1beta1.code_pb2 import CODE_OK

from exceptions.exceptions import AuthenticationException, SecretNotSetException
from config import Config


class Auth:
    """
    Auth class to handle authentication and token validation with CS3 Gateway API.
    """

    def __init__(self, config: Config, log: logging.Logger, gateway: GatewayAPIStub) -> None:
        """
        Initializes the Auth class with configuration, logger, and gateway stub,
        NOTE that token OR the client secret has to be set when instantiating the auth object.

        :param config: Config object containing the configuration parameters.
        :param log: Logger instance for logging.
        :param gateway: GatewayAPIStub instance for interacting with CS3 Gateway.
        """
        self._gateway: GatewayAPIStub = gateway
        self._log: logging.Logger = log
        self._config: Config = config
        # The user should be able to change the client secret (e.g. token) at runtime
        self._client_secret: str | None = None
        self._token: str | None = None

    def set_token(self, token: str) -> None:
        """
        Should be used if the user wishes to set the reva token directly, instead of letting the client
        exchange credentials for the token. NOTE that token OR the client secret has to be set when
        instantiating the client object.

        :param token: The reva token.
        """
        self._token = token

    def set_client_secret(self, token: str) -> None:
        """
        Sets the client secret, exists so that the user can change the client secret (e.g. token, password) at runtime,
        without having to create a new Auth object. NOTE that token OR the client secret has to be set when
        instantiating the client object.

        :param token: Auth token/password.
        """
        self._client_secret = token

    def get_token(self) -> tuple[str, str]:
        """
        Attempts to get a valid authentication token. If the token is not valid, a new token is requested
        if the client secret is set, if only the token is set then an exception will be thrown stating that
        the credentials have expired.

        :return tuple: A tuple containing the header key and the token.
                       May throw AuthenticationException (token expired, or failed to authenticate)
                       or SecretNotSetException (neither token or client secret was set).
        """

        if not Auth._check_token(self._token):
            # Check that client secret or token is set
            if not self._client_secret and not self._token:
                self._log.error("Attempted to authenticate, neither client secret or token was set.")
                raise SecretNotSetException("The client secret (e.g. token, passowrd) is not set")
            elif not self._client_secret and self._token:
                # Case where ONLY a token is provided but it has expired
                self._log.error("The provided token have expired")
                raise AuthenticationException("The credentials have expired")
            # Create an authentication request
            req = gw.AuthenticateRequest(
                type=self._config.auth_login_type,
                client_id=self._config.auth_client_id,
                client_secret=self._client_secret,
            )
            # Send the authentication request to the CS3 Gateway
            res = self._gateway.Authenticate(req)

            if res.status.code != CODE_OK:
                self._log.error(
                    f"Failed to authenticate user {self._config.auth_client_id}, error: {res.status.message}"
                )
                raise AuthenticationException(
                    f"Failed to authenticate user {self._config.auth_client_id}, error: {res.status.message}"
                )
            self._token = res.token
        return ("x-access-token", self._token)

    def list_auth_providers(self) -> list[str]:
        """
        list authentication providers

        :return: a list of the supported authentication types
                 May return ConnectionError (Could not connect to host)
        """
        try:
            res = self._gateway.ListAuthProviders(request=ListAuthProvidersRequest())
            if res.status.code != CODE_OK:
                self._log.error(f"List auth providers request failed, error: {res.status.message}")
                raise Exception(res.status.message)
        except grpc.RpcError as e:
            self._log.error("List auth providers request failed")
            raise ConnectionError(e)
        return res.types

    @classmethod
    def _check_token(cls, token: str) -> bool:
        """
        Checks if the given token is set and valid.

        :param token: JWT token as a string.
        :return: True if the token is valid, False otherwise.
        """
        if not token:
            return False
        # Decode the token without verifying the signature
        decoded_token = jwt.decode(jwt=token, algorithms=["HS256"], options={"verify_signature": False})
        now = datetime.datetime.now().timestamp()
        token_expiration = decoded_token.get("exp")
        if token_expiration and now > token_expiration:
            return False

        return True
