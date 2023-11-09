#!/usr/bin/env python3
""" Basic Auth"""
from api.v1.auth.auth import Auth
import base64
from re import search


class BasicAuth(Auth):
    """inherits from Auth"""

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        header = authorization_header.replace("Basic ", "")
        return header

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """returns the decoded value of a Base64 string"""
        if not base64_authorization_header:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            header_bytes = base64.b64decode(base64_authorization_header)
        except Exception as e:
            return None
        return header_bytes.decode("utf-8")

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """returns the user email and password from the Base64 decoded value"""
        decoded = decoded_base64_authorization_header
        if (decoded and isinstance(decoded, str) and
                ":" in decoded):
            res = decoded.split(":", 1)
            return (res[0], res[1])
        return (None, None)
