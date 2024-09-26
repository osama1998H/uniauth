# Adding new endpoint workflow
---

## **Overview**

In a FastAPI application structured as yours, adding a new endpoint involves:

1. **Defining the data models and schemas** (if needed).
2. **Creating or updating CRUD operations** (if needed).
3. **Creating a new endpoint function** in the appropriate module.
4. **Registering the endpoint with the API router**.
5. **Updating dependencies or utilities** (if needed).
6. **Testing the new endpoint**.

---

Let's assume we want to add a new endpoint that allows users to update their profile information. We'll call this endpoint `update_user_profile`.

---

## **Step-by-Step Guide**

### **1. Define the Data Schemas**

**Files to change:**

- `app/schemas/user.py`

**Why:**

Schemas define the shape of the data for requests and responses. We need to define a schema for the data that the user will send to update their profile.

**Action:**

- **Add a new schema class for the update operation.**

**Code:**

```python
# app/schemas/user.py

from pydantic import BaseModel, EmailStr, Field

class UserUpdate(BaseModel):
    email: EmailStr = Field(None, description="The user's email address")
    full_name: str = Field(None, description="The user's full name")
    password: str = Field(None, description="The user's new password")
```

**Explanation:**

- We create a `UserUpdate` schema that includes optional fields (`None` by default) for the user to update.

---

### **2. Update the CRUD Operations**

**Files to change:**

- `app/crud/crud_user.py`

**Why:**

The CRUD (Create, Read, Update, Delete) operations define how we interact with the database. We need to add a method to update a user's information.

**Action:**

- **Add a new method `update` to the `CRUDUser` class.**

**Code:**

```python
# app/crud/crud_user.py

from sqlalchemy.orm import Session
from typing import Any, Dict, Optional, Union
from app.models.user import User
from app.schemas.user import UserUpdate

class CRUDUser:
    # Existing methods...

    def update(
        self, db: Session, *, db_obj: User, obj_in: Union[UserUpdate, Dict[str, Any]]
    ) -> User:
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.model_dump(exclude_unset=True)
        for field in update_data:
            setattr(db_obj, field, update_data[field])
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

crud_user = CRUDUser(User)
```

**Explanation:**

- The `update` method takes the existing database object (`db_obj`) and the new data (`obj_in`), updates the fields, and commits the changes to the database.
- `obj_in.model_dump(exclude_unset=True)` ensures we only update the fields provided by the user.

---

### **3. Create or Update the Endpoint Module**

**Files to change:**

- `app/api/v1/endpoints/users.py`

**Why:**

We need to define the new API endpoint within the appropriate module. Since we're updating user information, we'll add it to `users.py`.

**Action:**

- **Add a new route handler function `update_user_profile`.**

**Code:**

```python
# app/api/v1/endpoints/users.py

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.user import User, UserUpdate
from app.api import deps
from app.crud.crud_user import crud_user

router = APIRouter()

# Existing endpoints...

@router.put("/me", response_model=User)
async def update_user_profile(
    *,
    db: Session = Depends(deps.get_db),
    user_in: UserUpdate,
    current_user: User = Depends(deps.get_current_active_user)
):
    """
    Update own user profile.
    """
    user = crud_user.update(db, db_obj=current_user, obj_in=user_in)
    return user
```

**Explanation:**

- We use the `@router.put("/me")` decorator to define a PUT endpoint at `/me`.
- The endpoint depends on `get_db` to get a database session and `get_current_active_user` to get the authenticated user.
- The `user_in` parameter will contain the data sent by the user to update their profile.
- We call the `update` method from `crud_user` to update the user in the database.
- The updated user object is returned as the response.

---

### **4. Update Dependencies (if needed)**

**Files to change:**

- `app/api/deps.py`

**Why:**

Dependencies provide reusable components like database sessions and authentication logic. We need to ensure `get_current_active_user` is available and works correctly.

**Action:**

- **Verify that `get_current_active_user` is correctly implemented.**

**Code:**

```python
# app/api/deps.py

from typing import Generator
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.core.security import verify_password
from app.models.user import User
from app.crud.crud_user import crud_user
from app.schemas.token import TokenPayload
from jose import jwt, JWTError
from app.core.config import settings

def get_db() -> Generator:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> User:
    # Token validation logic...
    return user

def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
```

**Explanation:**

- Ensure that `get_current_active_user` checks if the user is active.
- This dependency is used in the endpoint to ensure only authenticated and active users can update their profiles.

---

### **5. Update the API Router**

**Files to change:**

- `app/api/v1/api.py`

**Why:**

We need to ensure that the router from `users.py` is included in the main API router so that the new endpoint is accessible.

**Action:**

- **Verify that the users router is included.**

**Code:**

```python
# app/api/v1/api.py

from fastapi import APIRouter
from app.api.v1.endpoints import users, login

api_router = APIRouter()
api_router.include_router(login.router, prefix="/login", tags=["login"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
```

**Explanation:**

- The `users.router` is included with the prefix `/users`.
- Since our new endpoint is `/me`, it will be accessible at `/api/v1/users/me`.

---

### **6. Update the Main Application**

**Files to change:**

- `app/main.py`

**Why:**

Ensure that the main FastAPI application includes the API router.

**Action:**

- **Verify that the API router is included in the main app.**

**Code:**

```python
# app/main.py

from fastapi import FastAPI
from app.api.v1.api import api_router
from app.core.config import settings

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(api_router, prefix=settings.API_V1_STR)
```

**Explanation:**

- The `api_router` is included in the main app with the prefix specified in settings (`/api/v1`).

---

### **7. Update the Database Models (if needed)**

**Files to change:**

- `app/models/user.py`

**Why:**

If we are adding new fields to the user model, we need to update the database model and generate a new Alembic migration.

**Action (Optional):**

- **Add new fields to the `User` model.**

**Code:**

```python
# app/models/user.py

from sqlalchemy import Column, Integer, String, Boolean
from app.db.base_class import Base

class User(Base):
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, index=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    # Add any new fields here
```

**Explanation:**

- If the new endpoint requires changes to the database schema, we need to update the model and create a new migration.

**Generate a New Migration:**

```bash
alembic revision --autogenerate -m "Add new fields to User model"
alembic upgrade head
```

---

### **8. Test the New Endpoint**

**Why:**

To ensure the endpoint works as expected and to catch any issues.

**Action:**

- **Start the application and test the endpoint using a tool like curl, Postman, or the Swagger UI.**

**Testing via Swagger UI:**

1. Navigate to `http://localhost:8000/docs`.
2. Authenticate using the login endpoint to get a JWT token.
3. Use the `PUT /api/v1/users/me` endpoint.
4. Provide the token in the "Authorize" button or in the `Authorization` header as `Bearer <token>`.
5. Send a request with the data you want to update.

---

### **9. (Optional) Update Documentation**

**Files to change:**

- OpenAPI documentation is auto-generated from your code and docstrings.

**Why:**

Keeping your documentation up to date is important for API consumers.

**Action:**

- **Ensure your endpoint function has a descriptive docstring.**

**Code:**

```python
# app/api/v1/endpoints/users.py

@router.put("/me", response_model=User)
async def update_user_profile(
    *,
    db: Session = Depends(deps.get_db),
    user_in: UserUpdate,
    current_user: User = Depends(deps.get_current_active_user)
):
    """
    Update own user profile.

    This endpoint allows the current authenticated user to update their profile information.
    """
    user = crud_user.update(db, db_obj=current_user, obj_in=user_in)
    return user
```

**Explanation:**

- The docstring will appear in the Swagger UI, providing context and usage information.

---

### **10. (Optional) Add Unit Tests**

**Files to change:**

- Create a `tests/` directory if it doesn't exist.
- Add tests in `tests/test_users.py`.

**Why:**

Automated tests help ensure your code works as expected and prevent regressions.

**Action:**

- **Write test cases for the new endpoint.**

**Code:**

```python
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
```

**Explanation:**

- Tests the full flow: authentication and profile update.
- Checks that the response status is 200 and the data is updated.

---

## **Summary**

To add a new endpoint to your FastAPI application:

1. **Define or update the data schemas** in `app/schemas/` to represent the data structures used in requests and responses.

2. **Update the CRUD operations** in `app/crud/` to handle database interactions related to the new functionality.

3. **Create or update the endpoint module** in `app/api/v1/endpoints/` by adding the new path operation function.

4. **Register the endpoint** with the API router in `app/api/v1/api.py` to make it accessible through the API.

5. **Ensure dependencies** in `app/api/deps.py` are correctly implemented and provide the necessary utilities like authentication and database sessions.

6. **Update database models** in `app/models/` if the new endpoint requires changes to the data schema, and create migrations using Alembic.

7. **Test the endpoint** by running the application and using tools like Swagger UI, Postman, or automated tests.

8. **Update documentation** by providing descriptive docstrings and ensuring your code is self-documenting.

---

## **Why This Order Matters**

- **Data Schemas First:** Defining the schemas upfront ensures that the data validation is in place before you start writing the business logic.

- **CRUD Operations Next:** Updating CRUD operations allows you to interact with the database correctly when you implement your endpoint.

- **Endpoint Implementation:** With schemas and CRUD operations ready, you can now focus on the API logic.

- **Dependencies:** Ensuring your dependencies are up to date prevents runtime errors related to missing or incorrect dependencies.

- **API Router Registration:** Without registering the endpoint, it won't be accessible, so it's crucial to include it in the router.

- **Database Models and Migrations:** If your endpoint requires changes to the data schema, updating the models and migrations ensures data consistency.

- **Testing:** Testing after implementation helps catch any issues early and ensures your endpoint works as intended.

- **Documentation:** Keeping documentation updated aids both current and future developers in understanding how to use and maintain the API.

---

## **Final Thoughts**

By following these steps, you can methodically add new endpoints to your FastAPI application, ensuring that each component is correctly integrated and that your application remains stable and maintainable.

If you have any questions about any of these steps or need further clarification on specific parts, feel free to ask!