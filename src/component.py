import ftplib
import logging
import os
import socket
from datetime import datetime, UTC
from io import StringIO
from typing import Callable

import ssl
import backoff
import ftputil
import paramiko
from keboola.component.base import ComponentBase, sync_action
from keboola.component.exceptions import UserException

from configuration import Configuration, Protocol

MAX_RETRIES = 2

# img parameter names
KEY_HOSTNAME_IMG = "sftp_host"
KEY_PORT_IMG = "sftp_port"


def backoff_hdlr(details):
    logging.warning("Backing off {wait:0.1f} seconds after {tries} tries calling function {target}".format(**details))


def giving_up_hdlr(details):
    raise UserException("Too many retries, giving up calling {target}".format(**details))


class ExplicitFTPS(ftplib.FTP_TLS):
    """Explicit FTPS, with shared TLS session
    workaround from https://stackoverflow.com/questions/14659154/ftps-with-python-ftplib-session-reuse-required"""

    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(
                conn, server_hostname=self.host, session=self.sock.session
            )  # this is the fix
        return conn, size


class ImplicitFTPS(ftplib.FTP_TLS):
    """FTP_TLS subclass that automatically wraps sockets in SSL to support implicit FTPS.
    workaround from https://stackoverflow.com/a/36049814"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sock = None

    @property
    def sock(self):
        """Return the socket."""
        return self._sock

    @sock.setter
    def sock(self, value):
        """When modifying the socket, ensure that it is ssl wrapped."""
        if value is not None and not isinstance(value, ssl.SSLSocket):
            value = self.context.wrap_socket(value)
        self._sock = value


class Component(ComponentBase):
    def __init__(self):
        super().__init__()
        self.params = Configuration(**self.configuration.parameters)
        self._connection: paramiko.Transport = None
        self._sftp_client: paramiko.SFTPClient = None
        self._ftp_client: ftputil.FTPHost = None
        logging.getLogger("paramiko").level = logging.CRITICAL

    def run(self):
        self.init_connection()

        try:
            in_tables = self.get_input_tables_definitions()
            in_files = self.get_input_files_definitions(only_latest_files=True)

            for fl in in_tables + in_files:
                self._upload_file(fl)
        except Exception:
            raise
        finally:
            self._close_connection()

    def init_connection(self):
        port = self.configuration.image_parameters.get(KEY_PORT_IMG) or self.params.port
        host = self.configuration.image_parameters.get(KEY_HOSTNAME_IMG) or self.params.hostname
        if self.params.protocol in [Protocol.FTP, Protocol.EX_FTPS, Protocol.IM_FTPS]:
            self.connect_to_ftp_server(port, host, self.params.user, self.params.password)

        else:
            pkey = self.get_private_key()
            banner_timeout = self.params.banner_timeout

            if self.params.disabled_algorithms:
                disabled_algorithms = eval(self.params.disabled_algorithms)
            else:
                disabled_algorithms = {}

            self.connect_to_sftp_server(
                port, host, self.params.user, self.params.password, pkey, disabled_algorithms, banner_timeout
            )

    @backoff.on_exception(
        backoff.expo,
        (ConnectionError, FileNotFoundError, IOError, paramiko.SSHException),
        max_tries=MAX_RETRIES,
        on_backoff=backoff_hdlr,
        factor=2,
        on_giveup=giving_up_hdlr,
    )
    def connect_to_sftp_server(self, port, host, user, password, pkey, disabled_algorithms, banner_timeout):
        try:
            conn = paramiko.Transport((host, port), disabled_algorithms=disabled_algorithms)
            conn.banner_timeout = banner_timeout
            conn.connect(username=user, password=password, pkey=pkey)
        except paramiko.ssh_exception.AuthenticationException as e:
            raise UserException("Connection failed: recheck your authentication and host URL parameters") from e
        except socket.gaierror as e:
            raise UserException("Connection failed: recheck your host URL and port parameters") from e

        sftp = paramiko.SFTPClient.from_transport(conn)

        self._connection = conn
        self._sftp_client = sftp

    @backoff.on_exception(
        backoff.expo,
        (ConnectionError, FileNotFoundError, IOError),
        max_tries=MAX_RETRIES,
        on_backoff=backoff_hdlr,
        factor=2,
        on_giveup=giving_up_hdlr,
    )
    def connect_to_ftp_server(self, port, host, user, password):
        try:
            if self.params.protocol == Protocol.FTP:
                base = ftplib.FTP
            elif self.params.protocol == Protocol.EX_FTPS:
                base = ExplicitFTPS
            else:
                base = ImplicitFTPS

            session_factory = ftputil.session.session_factory(
                base_class=base,
                port=port,
                use_passive_mode=self.params.passive_mode,
                encrypt_data_channel=True,
                encoding=None,
                debug_level=None,
            )

            ftp_host = ftputil.FTPHost(host, user, password, session_factory=session_factory)

        except ftputil.error.FTPOSError as e:
            raise UserException("Connection failed: recheck your authentication and host URL parameters") from e

        self._ftp_client = ftp_host

    def _close_connection(self):
        try:
            if self._sftp_client:
                self._sftp_client.close()
            if self._connection:
                self._connection.close()
            if self._ftp_client:
                self._ftp_client.close()
        except Exception as e:
            logging.warning(f"Failed to close connection: {e}")

    def get_private_key(self):
        keystring = self.params.ssh.keys.private
        pkey = None
        if keystring:
            keyfile = StringIO(keystring.rstrip())
            passphrase = self.params.passphrase
            try:
                pkey = self._parse_private_key(keyfile, passphrase)
            except (paramiko.SSHException, IndexError) as e:
                logging.exception("Private Key is invalid")
                raise UserException("Failed to parse private Key") from e
        return pkey

    @staticmethod
    def _parse_private_key(keyfile, passphrase=None):
        # try all versions of encryption keys
        pkey = None
        failed = False
        try:
            pkey = paramiko.RSAKey.from_private_key(keyfile, password=passphrase)
        except paramiko.SSHException as e:
            logging.warning(f"RSS Private key invalid: {e}")
            failed = True
        # ECDSAKey
        if failed:
            try:
                pkey = paramiko.ECDSAKey.from_private_key(keyfile, password=passphrase)
                failed = False
            except (paramiko.SSHException, IndexError):
                logging.warning("ECDSAKey Private key invalid, trying Ed25519Key.")
                failed = True
        # Ed25519Key
        if failed:
            try:
                pkey = paramiko.Ed25519Key.from_private_key(keyfile, password=passphrase)
            except (paramiko.SSHException, IndexError) as e:
                logging.warning("Ed25519Key Private key invalid.")
                raise e
        return pkey

    def _upload_file(self, input_file):
        destination = self.get_output_destination(input_file)
        logging.info(f"File Source: {input_file.full_path}")
        logging.info(f"File Destination: {destination}")
        try:
            if self.params.protocol in [Protocol.FTP, Protocol.EX_FTPS, Protocol.IM_FTPS]:
                self._try_to_execute_operation(self._ftp_client.upload, input_file.full_path, destination)
            else:
                self._try_to_execute_operation(self._sftp_client.put, input_file.full_path, destination)
        except FileNotFoundError as e:
            raise UserException(
                f"Destination path: '{self.params.path}' in FTP Server not found, recheck the remote destination path"
            ) from e
        except PermissionError as e:
            raise UserException(
                f"Permission Error: you do not have permissions to write to '{self.params.path}',"
                f" choose a different directory on the FTP server"
            ) from e
        except ftputil.error.PermanentError as e:
            raise UserException(f"Error during attept to upload file: {e}") from e
        except ftputil.error.FTPIOError as e:
            raise UserException(f"SSL connection failed, require_ssl_reuse.: {e}") from e

    def get_output_destination(self, input_file):
        timestamp_suffix = ""
        if self.params.append_date:
            timestamp = datetime.now(UTC).strftime(self.params.append_date_format)
            timestamp_suffix = f"_{timestamp}"

        file_path = self.params.path
        if file_path[-1] != "/":
            file_path = f"{file_path}/"

        filename, file_extension = os.path.splitext(os.path.basename(input_file.name))
        return file_path + filename + timestamp_suffix + file_extension

    @backoff.on_exception(
        backoff.expo,
        (ConnectionError, IOError, paramiko.SSHException),
        max_tries=MAX_RETRIES,
        on_backoff=backoff_hdlr,
        factor=2,
        on_giveup=giving_up_hdlr,
    )
    def _try_to_execute_operation(self, operation: Callable, *args):
        return operation(*args)

    @sync_action("testConnection")
    def test_connection(self):
        try:
            self.init_connection()
        except Exception:
            raise
        finally:
            self._close_connection()


"""
        Main entrypoint
"""
if __name__ == "__main__":
    try:
        comp = Component()
        # this triggers the run method by default and is controlled by the configuration.action parameter
        comp.execute_action()
    except UserException as exc:
        logging.exception(exc)
        exit(1)
    except Exception as exc:
        logging.exception(exc)
        exit(2)
