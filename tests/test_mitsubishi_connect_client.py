"""Test the mitsubishi connect client."""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mitsubishi_connect_client.mitsubishi_connect_client import MitsubishiConnectClient
from mitsubishi_connect_client.token_state import TokenState

from . import (
    sample_remote_operaton_response,
    sample_vehicle,
    sample_vehicle_state,
    sample_vehicle_status,
)


class TestMitsubishiConnectClient(unittest.IsolatedAsyncioTestCase):
    """Test the mitsubishi connect client."""

    async def asyncSetUp(self) -> None:
        """Set up the test."""
        _client = MitsubishiConnectClient("username", "password")
        _token_dict = {
            "access_token": "12345",
            "refresh_token": "54321",
            "expires_in": 3600,
            "token_type": "bearer",
            "refresh_expires_in": 3600,
            "accountDN": "1256",
        }
        _token = TokenState(**_token_dict)
        self._token_dict = _token_dict
        self._client = _client
        self._token = _token

    @patch("aiohttp.ClientSession.request")
    async def test_login(self, mock_post: MagicMock) -> None:
        """Test the login function."""
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(self._token_dict)
        mock_post.return_value.__aenter__.return_value = mock_response
        await self._client.login()
        assert self._client.token == self._token

    @patch("aiohttp.ClientSession.request")
    async def test_refresh_token(self, mock_post: MagicMock) -> None:
        """Test the refresh_token function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(self._token_dict)
        mock_post.return_value.__aenter__.return_value = mock_response
        await self._client.refresh_token()
        assert self._client.token == self._token

    @patch("aiohttp.ClientSession.request")
    async def test_get_vehicles(self, mock_get: MagicMock) -> None:
        """Test the get_vehicles function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_vehicle)
        mock_get.return_value.__aenter__.return_value = mock_response
        vehicles = await self._client.get_vehicles()
        assert vehicles.vehicles[0].vin == "vin"

    @patch("aiohttp.ClientSession.request")
    async def test_get_vehicle_state(self, mock_get: MagicMock) -> None:
        """Test the get_vehicle_state function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_vehicle_state)
        mock_get.return_value.__aenter__.return_value = mock_response
        vehicle_state = await self._client.get_vehicle_state("test_vin")
        assert vehicle_state.vin == "1234567890ABCDEFG"

    @patch("aiohttp.ClientSession.request")
    async def test_stop_engine(self, mock_post: MagicMock) -> None:
        """Test the stop_engine function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_remote_operaton_response)
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

    @patch("aiohttp.ClientSession.request")
    async def test_start_engine(self, mock_post: MagicMock) -> None:
        """Test the start_engine function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_remote_operaton_response)
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await self._client.start_engine("test_vin")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.request")
    async def test_unlock_vehicle(self, mock_post: MagicMock) -> None:
        """Test the unlock_vehicle function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_remote_operaton_response)
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await self._client.unlock_vehicle("test_vin", "test_pin_token")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.request")
    async def test_get_nonce(self, mock_post: MagicMock) -> None:
        """Test the get_nonce function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = '{"serverNonce": "test_server_nonce"}'
        mock_post.return_value.__aenter__.return_value = mock_response
        nonce = await self._client.get_nonce("test_vin")
        assert "clientNonce" in nonce
        assert nonce["serverNonce"] == "test_server_nonce"

    @patch("aiohttp.ClientSession.request")
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

    @patch("aiohttp.ClientSession.request")
    async def test_get_status(self, mock_get: MagicMock) -> None:
        """Test the get_status function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_vehicle_status)
        mock_get.return_value.__aenter__.return_value = mock_response
        vehicle_status = await self._client.get_status("test_vin")
        assert vehicle_status is not None

    @patch("aiohttp.ClientSession.request")
    async def test_bad_response(self, mock_get: MagicMock) -> None:
        """Test a bad response function."""
        self._client.token = self._token
        mock_response = AsyncMock()
        mock_response.text.return_value = json.dumps(sample_vehicle_status)
        mock_get.return_value.__aenter__.return_value = mock_response
        mock_response.ok = False
        mock_response.status = 400
        with pytest.raises(Exception):  # noqa: B017, PT011
            await self._client.get_status("test_vin")

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
