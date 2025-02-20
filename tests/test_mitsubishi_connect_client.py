"""Test the mitsubishi connect client."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from mitsubishi_connect_client.mitsubishi_connect_client import MitsubishiConnectClient

from . import (
    remote_operation_response_test,
    test_vehicle_state_response,
    test_vehicles_response,
)


class TestMitsubishiConnectClient(unittest.IsolatedAsyncioTestCase):
    """Test the mitsubishi connect client."""

    async def test_init(self) -> None:
        """Test the init function."""
        client = MitsubishiConnectClient()
        assert client._base_url == "https://us-m.aerpf.com"

    async def test_init_with_url(self) -> None:
        """Test the init function."""
        client = MitsubishiConnectClient("https://example.com")
        assert client._base_url == "https://example.com"

    @patch("aiohttp.ClientSession.post")
    async def test_login(self, mock_post: MagicMock) -> None:
        """Test the login function."""
        client = MitsubishiConnectClient()
        mock_response = AsyncMock()
        mock_response.text.return_value = (
            '{"access_token": "test_token", "accountDN": "test_account"}'
        )
        mock_post.return_value.__aenter__.return_value = mock_response
        await client.login("test_user", "test_password")
        assert client.token == {
            "access_token": "test_token",
            "accountDN": "test_account",
        }

    @patch("aiohttp.ClientSession.get")
    async def test_get_vehicles(self, mock_get: MagicMock) -> None:
        """Test the get_vehicles function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}
        mock_response = AsyncMock()
        mock_response.text.return_value = test_vehicles_response
        mock_get.return_value.__aenter__.return_value = mock_response
        vehicles = await client.get_vehicles()
        assert vehicles.vehicles[0].vin == "vin"

    @patch("aiohttp.ClientSession.get")
    async def test_get_vehicle_state(self, mock_get: MagicMock) -> None:
        """Test the get_vehicle_state function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}
        mock_response = AsyncMock()
        mock_response.text.return_value = test_vehicle_state_response
        mock_get.return_value.__aenter__.return_value = mock_response
        vehicle_state = await client.get_vehicle_state("test_vin")
        assert vehicle_state.vin == "1234567890ABCDEFG"

    @patch("aiohttp.ClientSession.post")
    async def test_stop_engine(self, mock_post: MagicMock) -> None:
        """Test the stop_engine function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}
        mock_response = AsyncMock()
        mock_response.text.return_value = remote_operation_response_test
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await client.stop_engine("test_vin")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.post")
    async def test_flash_lights(self, mock_post: MagicMock) -> None:
        """Test the flash_lights function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}
        mock_response = AsyncMock()
        mock_response.text.return_value = remote_operation_response_test
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await client.flash_lights("test_vin")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.post")
    async def test_start_engine(self, mock_post: MagicMock) -> None:
        """Test the start_engine function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}
        mock_response = AsyncMock()
        mock_response.text.return_value = remote_operation_response_test
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await client.start_engine("test_vin")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.post")
    async def test_unlock_vehicle(self, mock_post: MagicMock) -> None:
        """Test the unlock_vehicle function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}
        mock_response = AsyncMock()
        mock_response.text.return_value = remote_operation_response_test
        mock_post.return_value.__aenter__.return_value = mock_response
        response = await client.unlock_vehicle("test_vin", "test_pin_token")
        assert response.status == "success"

    @patch("aiohttp.ClientSession.post")
    async def test_get_nonce(self, mock_post: MagicMock) -> None:
        """Test the get_nonce function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}
        mock_response = AsyncMock()
        mock_response.text.return_value = '{"serverNonce": "test_server_nonce"}'
        mock_post.return_value.__aenter__.return_value = mock_response
        nonce = await client.get_nonce("test_vin")
        assert "clientNonce" in nonce
        assert nonce["serverNonce"] == "test_server_nonce"

    @patch("aiohttp.ClientSession.post")
    async def test_get_pin_token(self, mock_post: MagicMock) -> None:
        """Test the get_pin_token function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}

        # Mock the get_nonce function
        mock_get_nonce = AsyncMock()
        mock_get_nonce.return_value = {
            "clientNonce": "test_client_nonce",
            "serverNonce": "test_server_nonce",
        }
        client.get_nonce = mock_get_nonce

        # Mock the API response for getting the PIN token
        mock_response = AsyncMock()
        mock_response.text.return_value = '{"pinToken": "test_pin_token"}'
        mock_post.return_value.__aenter__.return_value = mock_response

        pin_token = await client.get_pin_token("test_vin", "test_pin")
        assert pin_token == "test_pin_token"  # noqa: S105

    def test_add_headers_and_get_bytes(self) -> None:
        """Test the add_headers_and_get_bytes function."""
        client = MitsubishiConnectClient()
        client.token = {"access_token": "test_token", "accountDN": "test_account"}
        headers = {}
        data = {"test": "data"}
        json_bytes = client.add_headers_and_get_bytes(headers, data)
        assert headers["authorization"] == "Bearer test_token"
        assert json_bytes == b'{"test":"data"}'

    def test_generate_client_nonce_base64(self) -> None:
        """Test the generate_client_nonce_base64 function."""
        client = MitsubishiConnectClient()
        nonce = client.generate_client_nonce_base64()
        assert isinstance(nonce, str)
        forty_four = 44
        assert len(nonce) == forty_four

    def test_generate_hash(self) -> None:
        """Test the generate_hash function."""
        client = MitsubishiConnectClient()
        client_nonce = client.generate_client_nonce_base64()
        server_nonce = client.generate_client_nonce_base64()
        pin = "1234"
        hash_value = client.generate_hash(client_nonce, server_nonce, pin)
        assert isinstance(hash_value, str)
