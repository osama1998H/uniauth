# tests/test_users.py

import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_update_user_profile():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # First, authenticate to get a token
        response = await ac.post("/api/v1/login/access-token", data={"username": "test@example.com", "password": "password"})
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Now, update the user profile
        new_data = {"full_name": "New Name"}
        response = await ac.put("/api/v1/users/me", json=new_data, headers=headers)
        assert response.status_code == 200
        assert response.json()["full_name"] == "New Name"
