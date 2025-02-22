"""Test the mitsubishi connect client."""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from mitsubishi_connect_client.mitsubishi_connect_client import MitsubishiConnectClient
from mitsubishi_connect_client.token_state import TokenState

from . import (
    sample_remote_operaton_response,
    sample_vehicle,
    sample_vehicle_state,
)


class TestMitsubishiConnectClient(unittest.IsolatedAsyncioTestCase):
    """Test the mitsubishi connect client."""

    async def asyncSetUp(self) -> None:
            """Set up the test."""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            _client = MitsubishiConnectClient("username", "password")
            _token = TokenState(
                access_token="12345",  # noqa: S106
                refresh_token="54321",  # noqa: S106
                expires_in=3600,
                token_type="bearer",  # noqa: S106
                refresh_expires_in=3600,
                accountDN="1256",
            )
            self._client = _client
            self._token = _token


    @patch("aiohttp.ClientSession.request")
    async def test_login(self, mock_post: MagicMock) -> None:
        """Test the login function."""
        mock_response = AsyncMock()
        mock_response.text.return_value = self._token.model_dump_json()
        mock_post.return_value.__aenter__.return_value = mock_response
        await self._client.login()
        assert self._client.token == {
            "access_token": "test_token",
            "accountDN": "test_account",
        }

    @patch("aiohttp.ClientSession.get")
    async def test_get_vehicles(self, mock_get: MagicMock) -> None:
        """Test the get_vehicles function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_vehicle)
        mock_get.return_value.__aenter__.return_value = mock_response
        vehicles = await self._client.get_vehicles()
        assert vehicles.vehicles[0].vin == "vin"

    @patch("aiohttp.ClientSession.get")
    async def test_get_vehicle_state(self, mock_get: MagicMock) -> None:
        """Test the get_vehicle_state function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = sample_vehicle_state
        mock_get.return_value.__aenter__.return_value = mock_response
        vehicle_state = await self._client.get_vehicle_state("test_vin")
        assert vehicle_state.vin == "1234567890ABCDEFG"

    @patch("aiohttp.ClientSession.post")
    async def test_stop_engine(self, mock_post: MagicMock) -> None:
        """Test the stop_engine function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = sample_remote_operaton_response
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await self._client.stop_engine("test_vin")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.request")
    async def test_flash_lights(self, mock_post: MagicMock) -> None:
        """Test the flash_lights function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_remote_operaton_response)
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await self._client.flash_lights("test_vin")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.post")
    async def test_start_engine(self, mock_post: MagicMock) -> None:
        """Test the start_engine function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = sample_remote_operaton_response
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await self._client.start_engine("test_vin")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.post")
    async def test_unlock_vehicle(self, mock_post: MagicMock) -> None:
        """Test the unlock_vehicle function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = sample_remote_operaton_response
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await self._client.unlock_vehicle("test_vin", "test_pin_token")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.post")
    async def test_get_nonce(self, mock_post: MagicMock) -> None:
        """Test the get_nonce function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = '{"serverNonce": "test_server_nonce"}'
        mock_post.return_value.__aenter__.return_value = mock_response
        nonce = await self._client.get_nonce("test_vin")
        assert "clientNonce" in nonce
        assert nonce["serverNonce"] == "test_server_nonce"

    @patch("aiohttp.ClientSession.post")
    async def test_get_pin_token(self, mock_post: MagicMock) -> None:
        """Test the get_pin_token function."""
        self._client.token = self._token

        # Mock the get_nonce function
        mock_get_nonce = AsyncMock()
        mock_get_nonce.return_value = {
            "clientNonce": "test_client_nonce",
            "serverNonce": "test_server_nonce",
        }
        self._client.get_nonce = mock_get_nonce

        # Mock the API response for getting the PIN token
        mock_response = AsyncMock()
        mock_response.text.return_value = '{"pinToken": "test_pin_token"}'
        mock_post.return_value.__aenter__.return_value = mock_response

        pin_token = await self._client.get_pin_token("test_vin", "test_pin")
        assert pin_token == "test_pin_token"  # noqa: S105

    def test_generate_client_nonce_base64(self) -> None:
        """Test the generate_client_nonce_base64 function."""
        nonce = self._client._generate_client_nonce_base64()
        assert isinstance(nonce, str)
        forty_four = 44
        assert len(nonce) == forty_four

    def test_generate_hash(self) -> None:
        """Test the generate_hash function."""
        client_nonce = self._client._generate_client_nonce_base64()
        server_nonce = self._client._generate_client_nonce_base64()
        pin = "1234"
        hash_value = self._client._generate_hash(client_nonce, server_nonce, pin)
        assert isinstance(hash_value, str)
