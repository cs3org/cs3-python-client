"""
file.py

Authors: Rasmus Welander, Diogo Castro, Giuseppe Lo Presti.
Emails: rasmus.oscar.welander@cern.ch, diogo.castro@cern.ch, giuseppe.lopresti@cern.ch
Last updated: 02/08/2024
"""

import time
import logging
import http
import requests
import cs3.storage.provider.v1beta1.resources_pb2 as cs3spr
import cs3.storage.provider.v1beta1.provider_api_pb2 as cs3sp
from cs3.gateway.v1beta1.gateway_api_pb2_grpc import GatewayAPIStub
import cs3.rpc.v1beta1.code_pb2 as cs3code
import cs3.types.v1beta1.types_pb2 as types

from config import Config
from typing import Generator
from exceptions.exceptions import AuthenticationException, FileLockedException, NotFoundException, UnknownException
from cs3resource import Resource
from auth import Auth


class File:
    """
    File class to interact with the CS3 API.
    """

    def __init__(self, config: Config, log: logging.Logger, gateway: GatewayAPIStub, auth: Auth) -> None:
        self._auth: Auth = auth
        self._config: Config = config
        self._log: logging.Logger = log
        self._gateway: GatewayAPIStub = gateway

    # Note that res is of type any because it can be different types of respones
    # depending on the method that calls this function, I do not think importing
    # all the possible response types is a good idea
    def _log_not_found_info(self, resource: Resource, res: any, operation: str) -> None:
        self._log.info(
            f'msg="File not found on {operation}" {resource.get_file_ref_str()} '
            f'userid="{self._config.auth_client_id}" trace="{res.status.trace}" '
            f'reason="{res.status.message.replace('"', "'")}"'
        )

    def _log_precondition_info(self, resource: Resource, res: any, operation: str) -> None:
        self._log.info(
            f'msg="Failed precondition on {operation}" {resource.get_file_ref_str()} '
            f'userid="{self._config.auth_client_id}" trace="{res.status.trace}" '
            f'reason="{res.status.message.replace('"', "'")}"'
        )

    def _log_authentication_error(self, resource: Resource, res: any, operation: str) -> None:
        self._log.error(
            f'msg="Authentication failed on {operation}" {resource.get_file_ref_str()} '
            f'userid="{self._config.auth_client_id}" trace="{res.status.trace}" '
            f'reason="{res.status.message.replace('"', "'")}"'
        )

    def _log_unknown_error(self, resource: Resource, res: any, operation: str) -> None:
        self._log.error(
            f'msg="Failed to {operation}, unknown error" {resource.get_file_ref_str()} '
            f'userid="{self._config.auth_client_id}" trace="{res.status.trace}" '
            f'reason="{res.status.message.replace('"', "'")}"'
        )

    def _handle_errors(self, resource: Resource, res: any, operation: str) -> None:
        if res.status.code == cs3code.CODE_NOT_FOUND:
            self._log_not_found_info(resource, res, operation)
            raise NotFoundException(message=f"No such file or directory: {res.status.message}")
        if res.status.code in [cs3code.CODE_FAILED_PRECONDITION, cs3code.CODE_ABORTED]:
            self._log_precondition_info(resource, res, operation)
            raise FileLockedException(message=f"Lock mismatch or lock expired:  {res.status.message}")
        if res.status.code == cs3code.CODE_UNAUTHENTICATED:
            self._log_authentication_error(resource, res, operation)
            raise AuthenticationException(message=f"Operation not permitted:  {res.status.message}")
        if res.status.code != cs3code.CODE_OK:
            if "path not found" in str(res):
                self._log.info(f'msg="Invoked {operation} on missing file" {resource.get_file_ref_str()}')
                raise NotFoundException(message=f"No such file or directory:  {res.status.message}")
            self._log_unknown_error(resource, res, operation)
            raise UnknownException(message=f"Unknown error:  {res.status.message}")

    def stat(self, resource: Resource) -> cs3spr.ResourceInfo:
        """
        Stat a file and return the ResourceInfo object.

        :param resource: resource to stat.
        :return: cs3.storage.provider.v1beta1.resources_pb2.ResourceInfo (success)
                  NotFoundException (File not found),
                  AuthenticationException (Authentication Failed),
                  or UnknownException (Unknown Error).

        """
        tstart = time.time()
        res = self._gateway.Stat(request=cs3sp.StatRequest(ref=resource.ref), metadata=[self._auth.get_token()])
        tend = time.time()
        self._handle_errors(resource, res, "stat")
        self._log.debug(
            f'msg="Invoked Stat" {resource.get_file_ref_str()} elapsedTimems="{(tend - tstart) * 1000:.1f}"'
        )
        return res.info

    def set_xattr(self, resource: Resource, key: str, value: str) -> None:
        """
        Set the extended attribute <key> to <value> for a resource.

        :param resource: resource that has the attribute.
        :param key: attribute key.
        :param value: value to set.
        :return: None (Success)
                 May return FileLockedException (File is locked),
                 AuthenticationException (Authentication Failed),
                 or UnknownException (Unknown error).
        """
        md = cs3spr.ArbitraryMetadata()
        md.metadata.update({key: value})  # pylint: disable=no-member
        req = cs3sp.SetArbitraryMetadataRequest(ref=resource.ref, arbitrary_metadata=md)
        res = self._gateway.SetArbitraryMetadata(request=req, metadata=[self._auth.get_token()])
        # CS3 storages may refuse to set an xattr in case of lock mismatch: this is an overprotection,
        # as the lock should concern the file's content, not its metadata, however we need to handle that
        self._handle_errors(resource, res, "set extended attribute")
        self._log.debug(f'msg="Invoked setxattr" result="{res}"')

    def remove_xattr(self, resource: Resource, key: str) -> None:
        """
        Remove the extended attribute <key>.

        :param resource: cs3client resource.
        :param key: key for attribute to remove.
        :return: None (Success)
                 May return FileLockedException (File is locked),
                 AuthenticationException (Authentication failed) or
                 UnknownException (Unknown error).
        """
        req = cs3sp.UnsetArbitraryMetadataRequest(ref=resource.ref, arbitrary_metadata_keys=[key])
        res = self._gateway.UnsetArbitraryMetadata(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(resource, res, "remove extended attribute")
        self._log.debug(f'msg="Invoked rmxattr" result="{res.status}"')

    def rename_file(self, resource: Resource, newresource: Resource) -> None:
        """
        Rename/move resource to new resource.

        :param resource: Original resource.
        :param newresource: New resource.
        :return: None (Success)
                 May return NotFoundException (Original resource not found),
                 FileLockException (Resource is locked),
                 AuthenticationException (Authentication Failed),
                 UnknownException (Unknown Error).
        """
        req = cs3sp.MoveRequest(source=resource.ref, destination=newresource.ref)
        res = self._gateway.Move(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(resource, res, "rename file")
        self._log.debug(f'msg="Invoked renamefile" result="{res}"')

    def remove_file(self, resource: Resource) -> None:
        """
        Remove a resource.

        :param resource:  Resource to remove.
        :return: None (Success)
                 May return AuthenticationException (Authentication Failed),
                 NotFoundException (Resource not found) or
                 UnknownException (Unknown error).
        """
        req = cs3sp.DeleteRequest(ref=resource.ref)
        res = self._gateway.Delete(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(resource, res, "remove file")
        self._log.debug(f'msg="Invoked removefile" result="{res}"')

    def touch_file(self, resource: Resource) -> None:
        """
        Create a resource.

        :param resource: Resource to create.
        :return: None (Success)
                 May return FileLockedException (File is locked),
                 AuthenticationException (Authentication Failed) or
                 UnknownException (Unknown error)
        """
        req = cs3sp.TouchFileRequest(
            ref=resource.ref,
            opaque=types.Opaque(map={"Upload-Length": types.OpaqueEntry(decoder="plain", value=str.encode("0"))}),
        )
        res = self._gateway.TouchFile(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(resource, res, "touch file")
        self._log.debug(f'msg="Invoked touchfile" result="{res}"')

    def write_file(self, resource: Resource, content: str | bytes, size: int) -> None:
        """
        Write a file using the given userid as access token. The entire content is written
        and any pre-existing file is deleted (or moved to the previous version if supported),
        writing a file with size 0 is equivalent to "touch file" and should be used if the
        implementation does not support touchfile.

        :param resource: Resource to write content to.
        :param content: content to write
        :param size: size of content (optional)
        :return: None (Success)
                 May return FileLockedException (File is locked),
                 AuthenticationException (Authentication failed) or
                 UnknownException (Unknown error),

        """
        tstart = time.time()
        # prepare endpoint
        if size == -1:
            if isinstance(content, str):
                content = bytes(content, "UTF-8")
            size = len(content)
        req = cs3sp.InitiateFileUploadRequest(
            ref=resource.ref,
            opaque=types.Opaque(map={"Upload-Length": types.OpaqueEntry(decoder="plain", value=str.encode(str(size)))}),
        )
        res = self._gateway.InitiateFileUpload(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(resource, res, "write file")
        tend = time.time()
        self._log.debug(
            f'msg="writefile: InitiateFileUploadRes returned" trace="{res.status.trace}" protocols="{res.protocols}"'
        )

        # Upload
        try:
            protocol = [p for p in res.protocols if p.protocol in ["simple", "spaces"]][0]
            if self._config.tus_enabled:
                headers = {
                    "Tus-Resumable": "1.0.0",
                    "File-Path": resource.file,
                    "File-Size": str(size),
                    "X-Reva-Transfer": protocol.token,
                    **dict([self._auth.get_token()]),
                }
            else:
                headers = {
                    "Upload-Length": str(size),
                    "X-Reva-Transfer": protocol.token,
                    **dict([self._auth.get_token()]),
                }
            putres = requests.put(
                url=protocol.upload_endpoint,
                data=content,
                headers=headers,
                verify=self._config.ssl_verify,
                timeout=self._config.http_timeout,
            )
        except requests.exceptions.RequestException as e:
            self._log.error(f'msg="Exception when uploading file to Reva" reason="{e}"')
            raise IOError(e) from e
        if putres.status_code == http.client.CONFLICT:
            self._log.info(
                f'msg="Got conflict on PUT, file is locked" reason="{putres.reason}" {resource.get_file_ref_str()}'
            )
            raise FileLockedException(f"Lock mismatch or lock expired: {putres.reason}")
        if putres.status_code == http.client.UNAUTHORIZED:
            self._log_authentication_error(resource, putres, "write")
            raise AuthenticationException(f"Operation not permitted: {putres.reason}")
        if putres.status_code != http.client.OK:
            if (
                size == 0
            ):  # 0-byte file uploads may have been finalized after InitiateFileUploadRequest, let's assume it's OK
                # Should use TouchFileRequest instead
                self._log.info(
                    f'msg="0-byte file written successfully" {resource.get_file_ref_str()} '
                    f' elapsedTimems="{(tend - tstart) * 1000:.1f}"'
                )
                return

            self._log.error(
                f'msg="Error uploading file to Reva" code="{putres.status_code}" reason="{putres.reason}"'
            )
            raise IOError(putres.reason)
        self._log.info(
            f'msg="File written successfully" {resource.get_file_ref_str()} '
            f'elapsedTimems="{(tend - tstart) * 1000:.1f}"'
        )

    def read_file(self, resource: Resource) -> Generator[bytes, None, None]:
        """
        Read a file. Note that the function is a generator, managed by the app server.

        :param resource: Resource to read.
        :return: Generator[Bytes, None, None] (Success)
                 May return NotFoundException (Resource not found),
                 AuthenticationException (Authentication Failed) or
                 UnknownException (Unknown Error).
        """
        tstart = time.time()

        # prepare endpoint
        req = cs3sp.InitiateFileDownloadRequest(ref=resource.ref)
        res = self._gateway.InitiateFileDownload(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(resource, res, "read file")
        tend = time.time()
        self._log.debug(
            f'msg="readfile: InitiateFileDownloadRes returned" trace="{res.status.trace}" protocols="{res.protocols}"'
        )

        # Download
        try:
            protocol = [p for p in res.protocols if p.protocol in ["simple", "spaces"]][0]
            headers = {"X-Reva-Transfer": protocol.token, **dict([self._auth.get_token()])}
            fileget = requests.get(
                url=protocol.download_endpoint,
                headers=headers,
                verify=self._config.ssl_verify,
                timeout=self._config.http_timeout,
                stream=True,
            )
        except requests.exceptions.RequestException as e:
            self._log.error(f'msg="Exception when downloading file from Reva" reason="{e}"')
            raise IOError(e)
        data = fileget.iter_content(self._config.chunk_size)
        if fileget.status_code != http.client.OK:
            self._log.error(
                f'msg="Error downloading file from Reva" code="{fileget.status_code}" '
                f'reason="{fileget.reason.replace('"', "'")}"'
            )
            raise IOError(fileget.reason)
        else:
            self._log.info(
                f'msg="File open for read" {resource.get_file_ref_str()} elapsedTimems="{(tend - tstart) * 1000:.1f}"'
            )
            for chunk in data:
                yield chunk

    def make_dir(self, resource: Resource) -> None:
        """
        Create a directory.

        :param resource: Direcotry to create.
        :return: None (Success)
                 May return FileLockedException (File is locked),
                 AuthenticationException (Authentication failed) or
                 UnknownException (Unknown error).
        """
        req = cs3sp.CreateContainerRequest(ref=resource.ref)
        res = self._gateway.CreateContainer(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(resource, res, "make directory")
        self._log.debug(f'msg="Invoked CreateContainer" result="{res}"')

    def list_dir(
            self, resource: Resource
    ) -> Generator[cs3spr.ResourceInfo, None, None]:
        """
        List the contents of a directory, note that the function is a generator.

        :param resource: the directory.
        :return: Generator[cs3.storage.provider.v1beta1.resources_pb2.ResourceInfo, None, None] (Success)
                 May return NotFoundException (Resrouce not found),
                 AuthenticationException (Authentication Failed) or
                 UnknownException (Unknown error).
        """
        req = cs3sp.ListContainerRequest(ref=resource.ref)
        res = self._gateway.ListContainer(request=req, metadata=[self._auth.get_token()])
        self._handle_errors(resource, res, "list directory")
        self._log.debug(f'msg="Invoked ListContainer" result="{res}"')
        for info in res.infos:
            yield info
