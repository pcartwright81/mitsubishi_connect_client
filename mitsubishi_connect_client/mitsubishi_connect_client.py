"""Client for Mitsubishi Connect."""

import base64
import hashlib
import hmac
import json
import os
from typing import Any, ClassVar

import async_timeout
from aiohttp import ClientSession

from mitsubishi_connect_client.remote_operation_response import RemoteOperationResponse
from mitsubishi_connect_client.token_state import TokenState
from mitsubishi_connect_client.vehicle import VechiclesResponse
from mitsubishi_connect_client.vehicle_state import VehicleState
from mitsubishi_connect_client.vehicle_status import (
    VehicleStatusResponse,
    VhrItem,
)


class MitsubishiConnectClient:
    """Define the Mitsubishi Connect Client."""

    def __init__(
        self,
        user_name: str,
        password: str,
    ) -> None:
        """Initialize the client."""
        self._user_name = user_name
        self._password = password
        self._base_url = "https://us-m.aerpf.com"

    token: TokenState

    headers: ClassVar[dict[str, str]] = {
        "content-type": "application/json; charset=UTF-8",
        "user-agent": "Mobile",
        "x-client-id": "mobile",
        "ampapikey": "3f5547161b5d4bdbbb2bf8b26c69d1de",
        "host": "us-m.aerpf.com:15443",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip",
    }

    async def login(self) -> None:
        """Login to the api."""
        url = f"{self._base_url}/auth/v1/token"
        data = {
            "grant_type": "password",
            "username": f"{self._user_name.strip()}",
            "password": f"{self._password.strip()}",
        }
        response = await self._api_wrapper(
            method="post",
            url=url,
            data=data,
            headers=self.headers,
        )
        self.token = TokenState(**response)

    async def refresh_token(self) -> None:
        """Login to the api."""
        url = f"{self._base_url}/auth/v1/token"
        data = {
            "grant_type": "refresh_token",
            "refresh_token": f"{self.token.refresh_token}",
        }
        response = await self._api_wrapper(
            method="post",
            url=url,
            data=data,
            headers=self.headers,
        )
        self.token = TokenState(**response)

    async def get_vehicles(self) -> VechiclesResponse:
        """Get the vehicles on the account."""
        url = f"{self._base_url}/user/v1/users/{self.token.account_dn}/vehicles"
        self.headers["authorization"] = "Bearer " + self.token.access_token
        response = await self._api_wrapper(
            method="get",
            url=url,
            headers=self.headers,
        )
        return VechiclesResponse(**response)

    async def get_vehicle_state(self, vin: str) -> VehicleState:
        """Get the vehicle state."""
        url = f"{self._base_url}/avi/v1/vehicles/{vin}/vehiclestate"
        self.headers["authorization"] = "Bearer " + self.token.access_token
        response = await self._api_wrapper(
            method="get",
            url=url,
            headers=self.headers,
        )
        return VehicleState(**response)

    def _get_bytes(self, data: dict[str, str]) -> bytes:
        """Get the bytes."""
        return json.dumps(data).replace(" ", "").encode("utf-8")

    async def _remote_operation_response(
        self, vin: str, operation: str
    ) -> RemoteOperationResponse:
        """Remote operation response."""
        url = f"{self._base_url}:15443/avi/v3/remoteOperation"
        data = {
            "vin": f"{vin}",
            "operation": f"{operation}",
            "forced": "true",
            "userAgent": "android",
        }
        headers = self._add_headers(self.headers, data)
        response = await self._api_wrapper(
            method="post",
            url=url,
            data_bytes=self._get_bytes(data),
            headers=headers,
        )
        return RemoteOperationResponse(**response)

    async def stop_engine(self, vin: str) -> RemoteOperationResponse:
        """Stop the engine."""
        operation = "engineOff"
        return await self._remote_operation_response(vin, operation)

    async def flash_lights(self, vin: str) -> RemoteOperationResponse:
        """Flash the lights."""
        operation = "lights"
        return await self._remote_operation_response(vin, operation)

    async def start_engine(self, vin: str) -> RemoteOperationResponse:
        """Start the engine."""
        operation = "remoteAC"
        return await self._remote_operation_response(vin, operation)

    async def unlock_vehicle(self, vin: str, pin_token: str) -> RemoteOperationResponse:
        """Unlock the vehicle."""
        url = f"{self._base_url}:15443/avi/v3/remoteOperation"
        data = {
            "vin": f"{vin}",
            "operation": "doorUnlock",
            "forced": "true",
            "pinToken": f"{pin_token}",
            "userAgent": "android",
        }
        headers = self._add_headers(self.headers, data)
        response = await self._api_wrapper(
            method="post",
            url=url,
            data_bytes=self._get_bytes(data),
            headers=headers,
        )
        return RemoteOperationResponse(**response)

    async def get_nonce(self, vin: str) -> dict[str, str]:
        """Get the server nonce."""
        url = f"{self._base_url}:15443/oauth/v3/remoteOperation"
        client_nonce = self._generate_client_nonce_base64()
        data = {
            "vin": f"{vin}",
            "clientNonce": f"{client_nonce}",
        }
        headers = self._add_headers(self.headers, data)
        response = await self._api_wrapper(
            method="post",
            url=url,
            data_bytes=self._get_bytes(data),
            headers=headers,
        )
        return {
            "clientNonce": client_nonce,
            "serverNonce": response["serverNonce"],
        }

    async def get_pin_token(self, vin: str, pin: str) -> str:
        """Get the pin token."""
        nonce = await self.get_nonce(vin)
        client_nonce = nonce["clientNonce"]
        server_nonce = nonce["serverNonce"]
        generated_hash = self._generate_hash(client_nonce, server_nonce, pin)
        url = f"{self._base_url}:15443/oauth/v3/remoteOperation/pin"
        client_nonce = self._generate_client_nonce_base64()
        data = {
            "vin": f"{vin}",
            "hash": f"{generated_hash}",
            "userAgent": "android",
        }
        headers = self._add_headers(self.headers, data)
        response = await self._api_wrapper(
            method="post",
            url=url,
            data_bytes=self._get_bytes(data),
            headers=headers,
        )
        return response["pinToken"]

    async def get_status(self, vin: str) -> VhrItem:
        """Get the vehicle status."""
        url = f"{self._base_url}:15443/avi/v1/vehicles/{vin}/vehicleStatus?count=1"
        self.headers["authorization"] = "Bearer " + self.token.access_token
        response = await self._api_wrapper(
            method="get",
            url=url,
            headers=self.headers,
        )
        return VehicleStatusResponse(**response).vhr[0]

    def _add_headers(
        self, headers: dict[str, str], data: dict[str, str]
    ) -> dict[str, str]:
        """Add headers to the request."""
        headers["authorization"] = "Bearer " + self.token.access_token
        data_bytes = self._get_bytes(data)
        length = len(data_bytes)
        headers["content-length"] = str(length)
        return headers

    async def _api_wrapper(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        data: Any | None = None,
        data_bytes: bytes | None = None,
    ) -> Any:
        """Get information from the API."""
        async with (
            async_timeout.timeout(10),
            ClientSession() as session,
            session.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                data=data_bytes,
            ) as response,
        ):
            if response.ok:
                text = await response.text()
                return json.loads(text)
            response.raise_for_status()
            return None

    def _generate_client_nonce_base64(self, length: int = 32) -> str:
        """Generate a random nonce and encodes it in Base64."""
        random_bytes = os.urandom(length)  # Generate random bytes
        return base64.b64encode(random_bytes).decode("utf-8")

    def _generate_hash(
        self, client_nonce: str, server_nonce: str, pin: str
    ) -> str | None:
        """Generate a custom hash based on client nonce, server nonce, and pin."""
        try:
            client_word_array = base64.b64decode(client_nonce)
            server_word_array = base64.b64decode(server_nonce)
            separator_word_array = b":"  # UTF-8 encoding

            # Construct the key (mimicking JavaScript concatenation)
            key_array = client_word_array + separator_word_array + server_word_array

            pin_array = pin.encode("utf-8")  # UTF-8 encoding

            hash256 = hmac.new(key_array, pin_array, hashlib.sha256).digest()

            hash128 = b""  # Initialize as bytes

            for i in range(4):
                word1 = hash256[i * 4 : (i * 4) + 4]  # Get 4 bytes
                word2 = hash256[(i + 4) * 4 : ((i + 4) * 4) + 4]
                word = bytes(x ^ y for x, y in zip(word1, word2, strict=False))
                # XOR the bytes
                hash128 += word

            return base64.b64encode(hash128).decode("utf-8")
        except (
            Exception  # noqa: BLE001
        ):
            return None
