"""Define a token state object."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TokenState(BaseModel):
    """Define a token state object."""

    access_token: str
    refresh_token: str
    refresh_expires_in: int
    token_type: str
    expires_in: int
    account_dn: str = Field(..., alias="accountDN")
