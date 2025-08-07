from enum import Enum

from keboola.component.exceptions import UserException
from pydantic import BaseModel, Field, ValidationError, field_validator


class Protocol(str, Enum):
    FTP = "ftp"
    FTPS = "ftps"
    SFTP = "sftp"


class SSHKeys(BaseModel):
    public: str = Field(default=None)
    private: str = Field(default=None, alias="#private")


class SSH(BaseModel):
    keys: SSHKeys = Field(default_factory=SSHKeys)


class Configuration(BaseModel):
    protocol: Protocol = Protocol.FTP
    port: int = 21
    hostname: str
    user: str
    password: str = Field(default=None, alias="#pass")
    ssh: SSH = Field(default_factory=SSH)
    path: str = Field(default=None)
    append_date: bool = False
    append_date_format: str = Field(default="%Y%m%d%H%M%S")
    banner_timeout: int = 15
    disabled_algorithms: str = Field(default=None)

    debug: bool = False

    @field_validator("protocol", mode="before")
    def case_insensitive_protocol(cls, v):
        return v.lower() if isinstance(v, str) else v

    @field_validator("ssh", mode="before")
    def ignore_empty_list_for_ssh(cls, v):
        """Handle case when empty dict is passed as list to the component"""
        return {} if v == [] else v

    def __init__(self, **data):
        try:
            super().__init__(**data)
        except ValidationError as e:
            error_messages = [f"{err['loc'][0]}: {err['msg']}" for err in e.errors()]
            raise UserException(f"Validation Error: {', '.join(error_messages)}")
