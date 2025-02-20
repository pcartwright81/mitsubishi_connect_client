"""Client for Mitsubishi Connect."""

import base64
import hashlib
import hmac
import json
import os
from typing import ClassVar

import aiohttp

from mitsubishi_connect_client.remote_operation_response import RemoteOperationResponse
from mitsubishi_connect_client.vehicle import VechiclesResponse
from mitsubishi_connect_client.vehicle_state import VehicleState


class MitsubishiConnectClient:
    """Define the Mitsubishi Connect Client."""

    def __init__(self, base_url: str | None = None) -> None:
        """Create and instance of the client."""
        self._base_url = "https://us-m.aerpf.com"
        if base_url is not None:
            self._base_url = base_url

    token: dict

    headers: ClassVar[dict[str, str]] = {
        "content-type": "application/json; charset=UTF-8",
        "user-agent": "Mobile",
        "x-client-id": "mobile",
        "ampapikey": "3f5547161b5d4bdbbb2bf8b26c69d1de",
        "host": "us-m.aerpf.com:15443",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip",
    }

    async def login(self, user_name: str, password: str) -> None:
        """Login to the api."""
        url = f"{self._base_url}/auth/v1/token"
        data = (
            '{"grant_type":"password","username":"'
            + user_name
            + '","password":"'
            + password
            + '"}'
        )

        async with (
            aiohttp.ClientSession() as session,
            session.post(url, data=data, headers=self.headers) as response,
        ):
            response_text = await response.text()
            self.token = json.loads(response_text)

    async def get_vehicles(self) -> VechiclesResponse:
        """Get the vehicles on the account."""
        url = f"{self._base_url}/user/v1/users/{self.token['accountDN']}/vehicles"
        self.headers["authorization"] = "Bearer " + self.token["access_token"]
        async with (
            aiohttp.ClientSession() as session,
            session.get(url, headers=self.headers) as response,
        ):
            response_text = await response.text()
            return VechiclesResponse.from_text(response_text)

    async def get_vehicle_state(self, vin: str) -> VehicleState:
        """Get the vehicle state."""
        url = f"{self._base_url}/avi/v1/vehicles/{vin}/vehiclestate"
        self.headers["authorization"] = "Bearer " + self.token["access_token"]
        async with (
            aiohttp.ClientSession() as session,
            session.get(url, headers=self.headers) as response,
        ):
            response_text = await response.text()
            return VehicleState.from_text(response_text)

    async def stop_engine(self, vin: str) -> RemoteOperationResponse:
        """Stop the engine."""
        url = f"{self._base_url}:15443/avi/v3/remoteOperation"
        data = {
            "vin": f"{vin}",
            "operation": "engineOff",
            "forced": "true",
            "userAgent": "android",
        }
        headers = self.headers
        json_bytes = self.add_headers_and_get_bytes(headers, data)
        async with (
            aiohttp.ClientSession() as session,
            session.post(url, data=json_bytes, headers=self.headers) as response,
        ):
            response_text = await response.text()
            return RemoteOperationResponse.from_text(response_text)

    async def flash_lights(self, vin: str) -> RemoteOperationResponse:
        """Flash the lights."""
        url = f"{self._base_url}:15443/avi/v3/remoteOperation"
        data = {
            "vin": f"{vin}",
            "operation": "lights",
            "forced": "true",
            "userAgent": "android",
        }
        headers = self.headers
        json_bytes = self.add_headers_and_get_bytes(headers, data)
        async with (
            aiohttp.ClientSession() as session,
            session.post(url, data=json_bytes, headers=headers) as response,
        ):
            response_text = await response.text()
            return RemoteOperationResponse.from_text(response_text)

    async def start_engine(self, vin: str) -> RemoteOperationResponse:
        """Start the engine."""
        url = f"{self._base_url}:15443/avi/v3/remoteOperation"
        data = {
            "vin": f"{vin}",
            "operation": "remoteAC",
            "forced": "true",
            "dt": {"pos": 1, "def": 0, "tmp": 1},
            "userAgent": "android",
        }
        headers = self.headers
        json_bytes = self.add_headers_and_get_bytes(headers, data)
        async with (
            aiohttp.ClientSession() as session,
            session.post(url, data=json_bytes, headers=headers) as response,
        ):
            response_text = await response.text()
            return RemoteOperationResponse.from_text(response_text)

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
        headers = self.headers
        json_bytes = self.add_headers_and_get_bytes(headers, data)
        async with (
            aiohttp.ClientSession() as session,
            session.post(url, data=json_bytes, headers=headers) as response,
        ):
            response_text = await response.text()
            return RemoteOperationResponse.from_text(response_text)

    async def get_nonce(self, vin: str) -> dict[str, str]:
        """Get the server nonce."""
        url = f"{self._base_url}:15443/oauth/v3/remoteOperation"
        client_nonce = self.generate_client_nonce_base64()
        data = {
            "vin": f"{vin}",
            "clientNonce": f"{client_nonce}",
        }
        headers = self.headers
        json_bytes = self.add_headers_and_get_bytes(headers, data)
        async with (
            aiohttp.ClientSession() as session,
            session.post(url, data=json_bytes, headers=headers) as response,
        ):
            response_text = await response.text()
            nonce_response = json.loads(response_text)
            return {
                "clientNonce": client_nonce,
                "serverNonce": nonce_response["serverNonce"],
            }

    async def get_pin_token(self, vin: str, pin: str) -> str:
        """Get the pin token."""
        nonce = await self.get_nonce(vin)
        client_nonce = nonce["clientNonce"]
        server_nonce = nonce["serverNonce"]
        generated_hash = self.generate_hash(client_nonce, server_nonce, pin)
        url = f"{self._base_url}:15443/oauth/v3/remoteOperation/pin"
        client_nonce = self.generate_client_nonce_base64()
        data = {
            "vin": f"{vin}",
            "hash": f"{generated_hash}",
            "userAgent": "android",
        }
        headers = self.headers
        json_bytes = self.add_headers_and_get_bytes(headers, data)
        async with (
            aiohttp.ClientSession() as session,
            session.post(url, data=json_bytes, headers=headers) as response,
        ):
            response_text = await response.text()
            pin_response = json.loads(response_text)
            return pin_response["pinToken"]

    def add_headers_and_get_bytes(
        self, headers: dict[str, str], data: dict[str, str]
    ) -> bytes:
        """Add headers to the request."""
        headers["authorization"] = "Bearer " + self.token["access_token"]
        json_bytes = json.dumps(data).replace(" ", "").encode("utf-8")
        length = len(json_bytes)
        headers["content-length"] = str(length)
        return json_bytes

    def generate_client_nonce_base64(self, length: int = 32) -> str:
        """Generate a random nonce and encodes it in Base64."""
        random_bytes = os.urandom(length)  # Generate random bytes
        return base64.b64encode(random_bytes).decode("utf-8")

    def generate_hash(
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
