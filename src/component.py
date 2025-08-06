'''
Created on 10. 10. 2018

@author: david esner
'''
import logging
import os
import socket
from datetime import datetime
from io import StringIO
from typing import Callable

import backoff
import paramiko
from keboola.component.base import sync_action, ComponentBase

MAX_RETRIES = 6

KEY_USER = 'user'
KEY_PASSWORD = '#pass'
KEY_HOSTNAME = 'hostname'
KEY_PORT = 'port'
KEY_REMOTE_PATH = 'path'
KEY_APPENDDATE = 'append_date'
KEY_APPENDDATE_FORMAT = 'append_date_format'
KEY_PRIVATE_KEY = '#private_key'
SSH_ELEMENT = 'ssh'
SSH_KEYS = 'keys'
KEY_PRIVATE = '#private'
# img parameter names
KEY_HOSTNAME_IMG = 'sftp_host'
KEY_PORT_IMG = 'sftp_port'

KEY_DISABLED_ALGORITHMS = 'disabled_algorithms'
KEY_BANNER_TIMEOUT = 'banner_timeout'

KEY_DEBUG = 'debug'
PASS_GROUP = [KEY_PRIVATE_KEY, KEY_PASSWORD, SSH_ELEMENT]

REQUIRED_PARAMETERS = [KEY_USER, PASS_GROUP, KEY_REMOTE_PATH]

APP_VERSION = '1.0.0'


def backoff_hdlr(details):
    logging.warning("Backing off {wait:0.1f} seconds after {tries} tries "
                    "calling function {target}".format(**details))


def giving_up_hdlr(details):
    raise UserException("Too many retries, giving up calling {target}".format(**details))


class UserException(Exception):
    pass


class Component(ComponentBase):
    def __init__(self):
        super().__init__()

        self._connection: paramiko.Transport = None
        self._sftp_client: paramiko.SFTPClient = None
        logging.getLogger("paramiko").level = logging.CRITICAL

    def validate_connection_configuration(self):
        try:
            self.validate_configuration_parameters(REQUIRED_PARAMETERS)
            if self.configuration.image_parameters:
                self.validate_image_parameters([KEY_HOSTNAME_IMG, KEY_PORT_IMG])
            else:
                self.validate_configuration_parameters([KEY_PORT, KEY_HOSTNAME])
        except ValueError as err:
            raise UserException(err) from err

    def run(self):
        '''
        Main execution code
        '''
        self.validate_connection_configuration()
        params = self.configuration.parameters
        pkey = self.get_private_key(params)
        port = self.configuration.image_parameters.get(KEY_PORT_IMG) or params[KEY_PORT]
        host = self.configuration.image_parameters.get(KEY_HOSTNAME_IMG) or params[KEY_HOSTNAME]

        if params.get(KEY_DISABLED_ALGORITHMS, False):
            disabled_algorithms = eval(params[KEY_DISABLED_ALGORITHMS])
        else:
            disabled_algorithms = {}

        banner_timeout = params.get(KEY_BANNER_TIMEOUT, 15)

        self.connect_to_server(port,
                               host,
                               params[KEY_USER],
                               params[KEY_PASSWORD],
                               pkey,
                               disabled_algorithms,
                               banner_timeout)
        try:
            in_tables = self.get_input_tables_definitions()
            in_files = self.get_input_files_definitions(only_latest_files=True)

            for fl in in_tables + in_files:
                self._upload_file(fl)
        except Exception:
            raise
        finally:
            self._close_connection()

        logging.info("Done.")

    @backoff.on_exception(backoff.expo,
                          (ConnectionError, FileNotFoundError, IOError, paramiko.SSHException),
                          max_tries=MAX_RETRIES, on_backoff=backoff_hdlr, factor=2, on_giveup=giving_up_hdlr)
    def connect_to_server(self, port, host, user, password, pkey, disabled_algorithms, banner_timeout):
        try:
            conn = paramiko.Transport((host, port), disabled_algorithms=disabled_algorithms)
            conn.banner_timeout = banner_timeout
            conn.connect(username=user, password=password, pkey=pkey)
        except paramiko.ssh_exception.AuthenticationException as e:
            raise UserException('Connection failed: recheck your authentication and host URL parameters') from e
        except socket.gaierror as e:
            raise UserException('Connection failed: recheck your host URL and port parameters') from e

        sftp = paramiko.SFTPClient.from_transport(conn)

        self._connection = conn
        self._sftp_client = sftp

    def _close_connection(self):
        try:
            if self._sftp_client:
                self._sftp_client.close()
            if self._connection:
                self._connection.close()
        except Exception as e:
            logging.warning(f"Failed to close connection: {e}")

    def get_private_key(self, params):
        ssh_element = params.get(SSH_ELEMENT) or {}  # handling the case when empty dict is passed as list
        keystring = params.get(KEY_PRIVATE_KEY) or ssh_element.get(SSH_KEYS, {}).get(KEY_PRIVATE)
        pkey = None
        if keystring:
            keyfile = StringIO(keystring.rstrip())
            try:
                pkey = self._parse_private_key(keyfile)
            except (paramiko.SSHException, IndexError) as e:
                logging.exception("Private Key is invalid")
                raise UserException("Failed to parse private Key") from e
        return pkey

    @staticmethod
    def _parse_private_key(keyfile):
        # try all versions of encryption keys
        pkey = None
        failed = False
        try:
            pkey = paramiko.RSAKey.from_private_key(keyfile)
        except paramiko.SSHException:
            logging.warning("RSS Private key invalid, trying DSS.")
            failed = True
        # DSS
        if failed:
            try:
                pkey = paramiko.DSSKey.from_private_key(keyfile)
                failed = False
            except (paramiko.SSHException, IndexError):
                logging.warning("DSS Private key invalid, trying ECDSAKey.")
                failed = True
        # ECDSAKey
        if failed:
            try:
                pkey = paramiko.ECDSAKey.from_private_key(keyfile)
                failed = False
            except (paramiko.SSHException, IndexError):
                logging.warning("ECDSAKey Private key invalid, trying Ed25519Key.")
                failed = True
        # Ed25519Key
        if failed:
            try:
                pkey = paramiko.Ed25519Key.from_private_key(keyfile)
            except (paramiko.SSHException, IndexError) as e:
                logging.warning("Ed25519Key Private key invalid.")
                raise e
        return pkey

    def _upload_file(self, input_file):
        params = self.configuration.parameters

        destination = self.get_output_destination(input_file)
        logging.info(f"File Source: {input_file.full_path}")
        logging.info(f"File Destination: {destination}")
        try:
            self._try_to_execute_sftp_operation(self._sftp_client.put, input_file.full_path, destination)
        except FileNotFoundError as e:
            raise UserException(
                f"Destination path: '{params[KEY_REMOTE_PATH]}' in SFTP Server not found,"
                f" recheck the remote destination path") from e
        except PermissionError as e:
            raise UserException(
                f"Permission Error: you do not have permissions to write to '{params[KEY_REMOTE_PATH]}',"
                f" choose a different directory on the SFTP server") from e

    def get_output_destination(self, input_file):
        params = self.configuration.parameters

        timestamp_suffix = ''
        if params[KEY_APPENDDATE]:
            timestamp = datetime.utcnow().strftime(params.get(KEY_APPENDDATE_FORMAT, '%Y%m%d%H%M%S'))
            timestamp_suffix = f"_{timestamp}"

        file_path = params[KEY_REMOTE_PATH]
        if file_path[-1] != "/":
            file_path = f"{file_path}/"

        filename, file_extension = os.path.splitext(os.path.basename(input_file.name))
        return file_path + filename + timestamp_suffix + file_extension

    @backoff.on_exception(backoff.expo,
                          (ConnectionError, IOError, paramiko.SSHException),
                          max_tries=MAX_RETRIES, on_backoff=backoff_hdlr, factor=2, on_giveup=giving_up_hdlr)
    def _try_to_execute_sftp_operation(self, operation: Callable, *args):
        return operation(*args)

    @sync_action('testConnection')
    def test_connection(self):
        if self.configuration.image_parameters:
            self.validate_image_parameters([KEY_HOSTNAME_IMG, KEY_PORT_IMG])
        else:
            self.validate_configuration_parameters([KEY_PORT, KEY_HOSTNAME])
        params = self.configuration.parameters
        pkey = self.get_private_key(params)
        port = self.configuration.image_parameters.get(KEY_PORT_IMG) or params[KEY_PORT]
        host = self.configuration.image_parameters.get(KEY_HOSTNAME_IMG) or params[KEY_HOSTNAME]
        banner_timeout = params.get(KEY_BANNER_TIMEOUT, 15)

        if params.get(KEY_DISABLED_ALGORITHMS, False):
            disabled_algorithms = eval(params[KEY_DISABLED_ALGORITHMS])
        else:
            disabled_algorithms = {}
        try:
            self.connect_to_server(port,
                                   host,
                                   params[KEY_USER],
                                   params[KEY_PASSWORD],
                                   pkey,
                                   disabled_algorithms,
                                   banner_timeout)

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
