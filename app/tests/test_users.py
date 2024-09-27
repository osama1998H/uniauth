# tests/test_users.py
import pytest
from httpx import AsyncClient
from app.main import app
from sqlalchemy.orm import Session
from app.crud.crud_user import crud_user
from app.schemas.user import UserCreate
from app.db.session import SessionLocal



# Create a test user before the tests run
@pytest.fixture(scope="function")
def setup_test_user():
    db: Session = SessionLocal()
    user_in = UserCreate(email="test@example.com", password="password", full_name="Test User")
    user = crud_user.create(db=db, obj_in=user_in)
    yield user
    # Teardown: Delete the user after the test is complete
    db.delete(user)
    db.commit()
    db.close()


@pytest.mark.asyncio
async def test_update_user_profile(setup_test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Authenticate to get a token
        response = await ac.post("/api/v1/login/access-token", data={"username": "test@example.com", "password": "password"})
        assert response.status_code == 200  # Ensure authentication succeeds
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Now, update the user profile
        new_data = {"full_name": "New Name"}
        response = await ac.put("/api/v1/users/me", json=new_data, headers=headers)
        assert response.status_code == 200
        assert response.json()["full_name"] == "New Name"


@pytest.mark.asyncio
async def test_register_user():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Create a new user via registration
        new_user_data = {
            "email": "newuser@example.com",
            "password": "password123",
            "full_name": "New User"
        }
        response = await ac.post("/api/v1/register", json=new_user_data)
        assert response.status_code == 200
        assert response.json()["email"] == "newuser@example.com"


@pytest.mark.asyncio
async def test_request_password_reset(setup_test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Request password reset
        response = await ac.post("/api/v1/password-reset/request", json={"email": "test@example.com"})
        assert response.status_code == 200
        assert "reset_token" in response.json()


@pytest.mark.asyncio
async def test_confirm_password_reset(setup_test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # First request a password reset to get the reset token
        response = await ac.post("/api/v1/password-reset/request", json={"email": "test@example.com"})
        reset_token = response.json()["reset_token"]

        # Now confirm the password reset using the token
        reset_data = {
            "email": "test@example.com",
            "token": reset_token,
            "new_password": "new_password123"
        }
        response = await ac.post("/api/v1/password-reset/confirm", json=reset_data)
        assert response.status_code == 200
        assert response.json()["message"] == "Password updated successfully"



@pytest.mark.asyncio
async def test_update_password(setup_test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Authenticate to get a token
        response = await ac.post("/api/v1/login/access-token", data={"username": "test@example.com", "password": "password"})
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Now update the password
        password_update_data = {
            "old_password": "password",
            "new_password": "new_password123"
        }
        response = await ac.put("/api/v1/password/update", json=password_update_data, headers=headers)
        assert response.status_code == 200



