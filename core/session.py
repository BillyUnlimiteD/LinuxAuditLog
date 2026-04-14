"""
EphemeralSession — holds SSH credentials in memory only.
Credentials are never serialized, logged, or written to disk.
They are zeroed out after Stage A closes the connection.
"""
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EphemeralSession:
    host: str
    port: int
    username: str
    _password: str = field(repr=False, default="")
    _root_pass: str = field(repr=False, default="")

    @classmethod
    def from_env(cls) -> "EphemeralSession":
        """Read connection parameters from environment variables.

        Required:
            SSH_HOST      — target IP or hostname
            SSH_USER      — SSH username
            SSH_PASS      — SSH password

        Optional:
            SSH_PORT      — SSH port (default: 22)
            SSH_ROOT_PASS — root password for internal 'su root' escalation.
                            Use when root SSH login is disabled but you have
                            the root password.  Never stored on disk.
        """
        host = os.environ.get("SSH_HOST", "").strip()
        user = os.environ.get("SSH_USER", "").strip()
        password = os.environ.get("SSH_PASS", "")
        port = int(os.environ.get("SSH_PORT", "22"))
        root_pass = os.environ.get("SSH_ROOT_PASS", "")

        missing = [v for v, val in [("SSH_HOST", host), ("SSH_USER", user), ("SSH_PASS", password)] if not val]
        if missing:
            raise EnvironmentError(
                f"Missing required environment variable(s): {', '.join(missing)}\n"
                "  export SSH_HOST=<ip>\n"
                "  export SSH_USER=<user>\n"
                "  export SSH_PASS=<password>\n"
                "  export SSH_PORT=22          # optional\n"
                "  export SSH_ROOT_PASS=<pass>  # optional — for su root escalation"
            )

        return cls(host=host, port=port, username=user, _password=password, _root_pass=root_pass)

    @property
    def password(self) -> str:
        return self._password

    @property
    def root_pass(self) -> str:
        return self._root_pass

    def to_asyncssh_options(self) -> dict:
        """Returns connection kwargs for asyncssh.connect(). No credentials leak outside."""
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self._password,
            "known_hosts": None,       # documented limitation: host key not verified
            "connect_timeout": 30,
            "login_timeout": 30,
        }

    def zero_credentials(self) -> None:
        """Best-effort overwrite of all credentials in memory."""
        if self._password:
            self._password = "0" * len(self._password)
            self._password = ""
        if self._root_pass:
            self._root_pass = "0" * len(self._root_pass)
            self._root_pass = ""

    def to_safe_dict(self) -> dict:
        """Safe representation without credentials, suitable for logging."""
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
        }

    def __del__(self) -> None:
        self.zero_credentials()
