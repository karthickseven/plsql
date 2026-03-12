import os
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from UserData import UserData
import uvicorn
import psycopg
import requests
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

conn_string = os.getenv("DATABASE_URL")

# Encryption key for storing access tokens — set ENCRYPTION_KEY in .env
# Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise RuntimeError("ENCRYPTION_KEY environment variable is not set")
fernet = Fernet(ENCRYPTION_KEY.encode())

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")


class AuthTokenRequest(BaseModel):
    auth_code: str
    redirect_uri: str = "postmessage"

def init_db():
    """Initialize database and create table if needed."""
    try:
        with psycopg.connect(conn_string) as conn:
            print("Connection established")
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS tokens (
                        id SERIAL PRIMARY KEY,
                        refresh_token VARCHAR(255)
                    );
                    CREATE TABLE IF NOT EXISTS userinfo (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255),
                        email VARCHAR(255),
                        profile VARCHAR(255)
                    );
                    CREATE TABLE IF NOT EXISTS access_tokens (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        encrypted_access_token TEXT NOT NULL,
                        encrypted_refresh_token TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                conn.commit()
    except Exception as e:
        print("Connection failed.")
        print(e)  # In production, use logging instead of print

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)

@app.post("/refreshtoken/{refresh_token}")
def refresh_token(refresh_token: str):
    """Store refresh token in database."""
    try:
        with psycopg.connect(conn_string) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tokens (refresh_token) VALUES (%s);",
                    (refresh_token,)
                )
                conn.commit()
        print(f"SUCCESS: Refresh token stored in DB")
        return {"message": f"Refresh token stored: {refresh_token}"}
    except Exception as e:
        print(f"FAILED: Could not store refresh token — {e}")
        return {"error": str(e)}
    
@app.post("/auth/token")
def exchange_auth_token(payload: AuthTokenRequest):
    """Exchange an auth code for access + refresh tokens, encrypt and store them."""
    # Step 1 — Exchange the authorisation code for tokens with Google
    token_response = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            "code": payload.auth_code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": payload.redirect_uri,
            "grant_type": "authorization_code",
        },
    )

    if token_response.status_code != 200:
        raise HTTPException(
            status_code=token_response.status_code,
            detail=f"Google token exchange failed: {token_response.text}",
        )

    token_data = token_response.json()
    access_token = token_data.get("access_token")
    refresh_token_value = token_data.get("refresh_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="No access token returned by Google")

    # Step 2 — Fetch user email from Google userinfo endpoint
    userinfo_resp = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if userinfo_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch user info from Google")

    email = userinfo_resp.json().get("email", "unknown")

    # Step 3 — Encrypt the tokens
    encrypted_access = fernet.encrypt(access_token.encode()).decode()
    encrypted_refresh = (
        fernet.encrypt(refresh_token_value.encode()).decode()
        if refresh_token_value
        else None
    )

    if refresh_token_value:
        print(f"SUCCESS: Refresh token received for {email}")
    else:
        print(f"WARNING: No refresh token returned by Google for {email}")

    # Step 4 — Store encrypted tokens in the database (upsert)
    try:
        with psycopg.connect(conn_string) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO access_tokens (email, encrypted_access_token, encrypted_refresh_token)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (email)
                    DO UPDATE SET encrypted_access_token = EXCLUDED.encrypted_access_token,
                                 encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
                                 created_at = CURRENT_TIMESTAMP;
                    """,
                    (email, encrypted_access, encrypted_refresh),
                )
                conn.commit()
        print(f"SUCCESS: Encrypted tokens stored in DB for {email}")
    except Exception as e:
        print(f"FAILED: Could not store tokens in DB for {email} — {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    return {
        "message": "Access token exchanged and stored (encrypted)",
        "email": email,
        "token_type": token_data.get("token_type"),
        "expires_in": token_data.get("expires_in"),
    }


@app.post("/userdata")
def store_user_data(userdata: UserData):
    """add user data to the database"""

    filtered_data = userdata.model_dump(exclude_unset=True)
    try:
        with psycopg.connect(conn_string) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO userinfo (id, name, email, profile) VALUES (%s, %s, %s, %s);",
                    (filtered_data["id"], filtered_data["name"], filtered_data["email"], filtered_data["profile"])
                )
                conn.commit()
        return {"message": "User data stored successfully"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    # Use PORT environment variable, default to 8080
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
