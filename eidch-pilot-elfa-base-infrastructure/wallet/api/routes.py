from fastapi import APIRouter, HTTPException, status
from typing import List, Dict
import httpx
import random
import uuid
import os
import logging
from binascii import hexlify, unhexlify
from common import u2sso
from pydantic import BaseModel, Field
from functools import lru_cache
from urllib.parse import urljoin
import hashlib
import uuid
from ast import literal_eval
import time
import logging
import asyncio 

logger = logging.getLogger(__name__)

# Create Pydantic models for request/response validation
class PasskeyResponse(BaseModel):
    passkey: str

class PasskeyRequest(BaseModel):
    key_name: str

class LoadPasskeyRequest(BaseModel):
    load_passkey: str

class RegisterRequest(BaseModel):
    passkey: str
    service_name: str
    challenge: str

class IdentityResponse(BaseModel):
    index: int

# Configuration class
class Settings:
    def __init__(self):
        self.registry_identity_url = "https://registry_identity:443"
        self.registry_identity_api_key = os.getenv("REGISTRY_IDENTITY_API_KEY")
        if not self.registry_identity_api_key:
            raise ValueError("REGISTRY_IDENTITY_API_KEY environment variable is not set")

@lru_cache()
def get_settings() -> Settings:
    return Settings()

router = APIRouter(tags=["U2SSO"])

settings = get_settings()
headers = {"X-API-Key": settings.registry_identity_api_key}
unique_id = uuid.uuid4()

@router.get("/hello")
async def hello():
    """Test endpoint"""
    return "hello"

@router.post("/create_passkey")
async def create_passkey(key_name: str) -> Dict[str, str]:
    """Create a new passkey"""
    try:
        u2sso.create_passkey(key_name)
        msk_bytes, success = u2sso.load_passkey(key_name)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not create and load passkey"
            )
        return {"passkey": hexlify(msk_bytes).decode()}
    except Exception as e:
        logger.error(f"Failed to create passkey: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/load_passkey")
async def load_passkey(key_path: str) -> Dict[str, str]:
    """Load an existing passkey"""
    msk_bytes, success = u2sso.load_passkey(key_path)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Could not load passkey"
        )
    return {"passkey": hexlify(msk_bytes).decode()}

def convert_str_to_bytes(id_str: str) -> bytes:
    """Convert string representation of bytes to actual bytes"""
    try:
        # Using literal_eval to safely evaluate the string representation of bytes
        return literal_eval(id_str)
    except (ValueError, SyntaxError) as e:
        logger.error(f"Failed to convert ID string to bytes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid ID format received from registry"
        )

@router.post("/register")
async def register(passkey: str, service_name: str, challenge: str) -> Dict[str, str]:
    try:
        # Convert hex inputs to bytes
        service_name_bytes = unhexlify(service_name)
        challenge_bytes = unhexlify(challenge)

        msk_bytes, success = u2sso.load_passkey(passkey)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not load passkey"
            )

        with httpx.Client(verify=False) as client:
            # Get topic list
            response = client.get(urljoin(settings.registry_identity_url, "identity/services"), headers=headers)
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to fetch services")
            topic_list = [unhexlify(topic) for topic in response.json()]
            topic_list_size = len(topic_list)

            # Get service index
            response = client.get(
                urljoin(settings.registry_identity_url, f"identity/service/{service_name}/index"),
                headers=headers
            )
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to get service index")
            topic_index = response.json()

            # Create ID and get index
            id_bytes = u2sso.create_id(msk_bytes, topic_list, topic_list_size)
            response = client.get(
                urljoin(settings.registry_identity_url, "identity/find"),
                params={"id_bytes": id_bytes.hex()},
                headers=headers
            )
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to find identity")
            id_index = response.json()

            # Ensure ID is registered
            if id_index == -1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="The SSO-ID for this passkey is not registered in the database"
                )

            # Get ID list
            response = client.get(urljoin(settings.registry_identity_url, "identity/ids"), headers=headers)
            id_list = response.json()
            id_list_bytes = [unhexlify(id_hex) for id_hex in id_list]
            id_size = len(id_list_bytes)

            # Calculate ring parameters like in the Python test
            N = 2
            M = 10
            current_m = 1
            ring_size = 1
            for i in range(1, M):
                ring_size = N * ring_size
                if ring_size >= id_size:
                    current_m = i
                    break

        
        # Create proof
        loop = asyncio.get_running_loop()
        print("Creating proof: parameters")
        print(f"ID index: {id_index}")
        print(f"Current m: {current_m}")
        print(f"ID size: {id_size}")
        print(f"Service name: {service_name_bytes}")
        print(f"Challenge: {challenge_bytes}")
        print(f"MSK: {msk_bytes}")
        print(f"ID list: {id_list_bytes}")
        print(f"Topic list: {topic_list}")
        print(f"Topic list size: {topic_list_size}")
        print(f"Topic index: {topic_index}")

        proof_hex, spk_bytes, nullifier_bytes, success = u2sso.registration_proof(
            id_index, current_m, id_size,
            service_name_bytes, challenge_bytes, msk_bytes,
            id_list_bytes, topic_list, topic_list_size, topic_index
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create registration proof"
            )

        print(f"Verification parameters")
        print(f"Proof: {proof_hex}")
        print(f"Current m: {current_m}")
        print(f"ID size: {id_size}")
        print(f"Service name: {service_name_bytes}")
        print(f"Challenge: {challenge_bytes}")
        print(f"ID list: {id_list_bytes}")
        print(f"SPK: {spk_bytes}")
        print(f"Topic list: {topic_list}")
        print(f"Topic list size: {topic_list_size}")
        print(f"Topic index: {topic_index}")
        print(f"Nullifier: {nullifier_bytes}")
        
        verified = u2sso.registration_verify(
            proof_hex, current_m, id_size,
            service_name_bytes, challenge_bytes, id_list_bytes,
            spk_bytes, topic_list, topic_list_size, topic_index, nullifier_bytes
        )

        if not verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Proof verification failed"
            )

        # Return the proof data
        return {
            "proof": proof_hex, 
            "spk": spk_bytes.hex(),
            "total_ids": str(id_size),
            "nullifier": nullifier_bytes.hex()
        }
      
        

    except HTTPException:
        raise
    except Exception as e:
        print(f"\nError in registration: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/auth")
async def authenticate(
    passkey: str,
    service_name: str,
    challenge: str
) -> Dict[str, str]:
    """Authenticate with a service"""
    try:
        service_name_bytes = unhexlify(service_name)
        challenge_bytes = unhexlify(challenge)

        msk_bytes, success = u2sso.load_passkey(passkey)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not load passkey"
            )
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(urljoin(settings.registry_identity_url, "identity/services"), headers=headers)
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to fetch services")
            topic_list = [unhexlify(topic) for topic in response.json()]
            topic_list_size = len(topic_list)

            loop = asyncio.get_running_loop()
            proof_auth_hex, val = await loop.run_in_executor(
                None,
                u2sso.auth_proof,
                service_name_bytes, challenge_bytes, msk_bytes, topic_list, topic_list_size
            )
            print(f"Authenticate - proof: {proof_auth_hex}")
            if val:
                return {
                    "proof auth hex format:": proof_auth_hex
                }
            else:
                return {
                    "error": "Authentication proof generation failed"
                }
    except Exception as e:
        logger.error(f"Failed to authenticate: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to authenticate: {str(e)}"
        )
        

@router.post("/create_identity")
async def create_identity(passkey: str):
    try:
        # Create and load passkey
        u2sso.create_passkey(passkey)
        msk_bytes, success = u2sso.load_passkey(passkey)
        print(f"Create identity - loaded passkey bytes: {msk_bytes.hex() if msk_bytes else 'None'}")
        
        # Get topic list
        url = urljoin(settings.registry_identity_url, "identity/services")
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(url, headers=headers)
            topic_list = response.json()
            topic_list = [unhexlify(topic) for topic in topic_list]
        print(f"Create identity - topic list: {topic_list}")
        len_topic_list = len(topic_list)

        # Create ID
        id_bytes = u2sso.create_id(msk_bytes, topic_list, len_topic_list)
        print(f"Create identity - generated ID: {id_bytes.hex()}")

        # Add logging for parameters being sent to registry
        params = {
            "id_bytes": id_bytes.hex(),
            "owner_id": str(uuid.uuid4())
        }
        print(f"Create identity - sending params to registry: {params}")

        print(f"Topic list for registration: {topic_list}")
        print(f"Loaded passkey bytes: {msk_bytes.hex() if msk_bytes else 'None'}")

        # Add identity
        url = urljoin(settings.registry_identity_url, "identity/add")
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(url, params=params, headers=headers)
            if response.status_code == 404:
                logger.error(f"Failed to add identity. Response: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to add identity to registry"
                )
            identity_index = response.json()
            
        return {
            "passkey": hexlify(msk_bytes).decode(),
            "owner_id": params["owner_id"],
            "identity_index": identity_index
        }
            
    except Exception as e:
        logger.error(f"Failed to create identity: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create identity: {str(e)}"
        )