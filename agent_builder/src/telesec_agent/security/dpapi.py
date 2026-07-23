"""Windows DPAPI protection for the enrolled machine credential."""

from __future__ import annotations

from typing import Protocol


class SecretProtectionError(RuntimeError):
    pass


class SecretProtector(Protocol):
    def protect(self, value: bytes) -> bytes: ...

    def unprotect(self, value: bytes) -> bytes: ...


class DpapiProtector:
    description = "Telesec Network Agent Credential"

    def protect(self, value: bytes) -> bytes:
        try:
            import win32crypt

            return win32crypt.CryptProtectData(
                value,
                self.description,
                None,
                None,
                None,
                0,
            )
        except Exception as exc:
            raise SecretProtectionError("Unable to protect agent credential") from exc

    def unprotect(self, value: bytes) -> bytes:
        try:
            import win32crypt

            _description, plaintext = win32crypt.CryptUnprotectData(
                value,
                None,
                None,
                None,
                0,
            )
            return plaintext
        except Exception as exc:
            raise SecretProtectionError("Unable to read agent credential") from exc
