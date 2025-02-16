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
        print("Starting registration process")
        print(f"Parameters: passkey={passkey}, service_name={service_name}")
        
        # Convert hex inputs to bytes
        service_name_bytes = unhexlify(service_name)
        challenge_bytes = unhexlify(challenge)
        
        async with httpx.AsyncClient(verify=False) as client:
            # Get topic list
            print("Fetching topic list")
            url = urljoin(settings.registry_identity_url, "identity/services")
            response = await client.get(url, headers=headers)
            topic_list = response.json()
            topic_list = [topic.encode('utf-8') for topic in topic_list]
            print(f"Retrieved topic list: {topic_list}")
            
            # Load passkey and create ID
            msk_bytes, success = u2sso.load_passkey(passkey)
            if not success:
                logger.error("Failed to load passkey")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not load passkey"
                )
                
            id_bytes = u2sso.create_id(msk_bytes, topic_list, len(topic_list))
            print(f"Created ID: {id_bytes.hex()}")
            
            # Check if identity exists
            url = urljoin(settings.registry_identity_url, "identity/find")
            params = {"id_bytes": id_bytes.hex()}
            response = await client.get(url, params=params, headers=headers)
            print(f"Identity lookup response: {response.status_code} - {response.content}")
            
            index = response.json()
            print(f"Retrieved index: {index}")
            
            if index == -1:
                logger.error("Identity not found in database")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Identity not found in database"
                )

            # Get all IDs for ring signature
            url = urljoin(settings.registry_identity_url, "identity/ids")
            response = await client.get(url, headers=headers)
            id_list = [bytes.fromhex(id_hex) for id_hex in response.json()]
            id_size = len(id_list)
            
            if id_size < 2:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="At least two SSO-IDs are required"
                )

            # Calculate ring parameters
            current_m = 1
            ring_size = 1
            for i in range(1, 10):  # M = 10
                ring_size = 2 * ring_size  # N = 2
                if ring_size >= id_size:
                    current_m = i
                    break
            
        # Get topic index
        print(f"Requesting service index for: {service_name}")
        url = urljoin(settings.registry_identity_url, f"identity/service/{service_name}/index")
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            response = await client.get(url, headers=headers)
    


        print("\n=== Registration Proof Parameters ===")
        print(f"index: {index}")
        print(f"current_m: {current_m}")
        print(f"current_N: {id_size}")
        print(f"service_name_bytes: {service_name_bytes.hex()}")
        print(f"challenge_bytes: {challenge_bytes.hex()}")
        print(f"msk_bytes: {msk_bytes.hex()}")
        print(f"id_list length: {len(id_list)}")
        print(f"topic_list: {topic_list}")
        print(f"topic_list_size: {len(topic_list)}")
        print(f"topic_index: {3}")
        print("================================\n")

        # Create registration proof
        proof_hex, spk_bytes, nullifier, val = u2sso.registration_proof(
            index=index,
            current_m=current_m,
            current_N=id_size,
            servicename=service_name_bytes,
            challenge=challenge_bytes,
            msk_bytes=msk_bytes,
            id_list=id_list,
            topic_list=topic_list,
            topic_list_size=len(topic_list),
            topic_index=3
        )
        
        if not val:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate registration proof"
            )

        return {
            "proof": proof_hex,
            "spk": spk_bytes.hex() if spk_bytes else None,
            "ring_size": id_size,
            "m": current_m,
            "nullifier": nullifier.hex() if nullifier else None,
        }
            
            
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/auth")
async def authenticate(
    passkey: str,
    service_name: str,
    challenge: str
) -> Dict[str, str]:
    """Authenticate with a service"""
    try:
        # Convert hex inputs to bytes
        service_name_bytes = unhexlify(service_name)
        challenge_bytes = unhexlify(challenge)

        msk_bytes, success = u2sso.load_passkey(passkey)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Could not load passkey"
        )


        async with httpx.AsyncClient() as client:
            topic_list = await client.get("http://registry_identity/services")
        print(topic_list)
        len_topic_list = len(topic_list)

        # Generate auth proof
        proof_hex, success = u2sso.auth_proof(
            servicename=service_name_bytes,
            challenge=challenge_bytes,
            msk_bytes=msk_bytes,
            topic_list=topic_list,
            topic_size=len_topic_list
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate auth proof"
            )

        return {"proof auth hex format:": proof_hex}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {str(e)}"
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
            topic_list = [topic.encode('utf-8') for topic in topic_list]
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