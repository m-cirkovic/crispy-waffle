import json
import logging
import uuid
from typing import List, Optional
from fastapi import FastAPI, Response, status, Form, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import httpx
from common.u2sso import u2sso
import fastapi
import hashlib
from urllib.parse import urljoin
import os
from functools import lru_cache
from binascii import hexlify, unhexlify
from common import u2sso
import ctypes
import asyncio

def get_memory_address(obj):
    return ctypes.addressof(ctypes.c_char.from_buffer(obj))

TAG = "U2SSO"

router = fastapi.APIRouter(tags=[TAG])

logger = logging.getLogger(__name__)

SERVICE_NAME = "Verifier_Name"

REGISTRY_URL = "https://registry_identity"
API_KEY = "tergum_dev_key"
servicename_bytes = hashlib.sha256(SERVICE_NAME.encode()).hexdigest()


class AuthChallenge(BaseModel):
    challenge: bytes
    user_ip: str

class Account(BaseModel):
    name: str
    spk: Optional[bytes] = None
    nullifier: Optional[bytes] = None
    challenge: bytes
    user_ip: str
    registered: bool = False
    proof: Optional[str] = None

class Settings:
    def __init__(self):
        self.registry_identity_url = "https://registry_identity:443"
        self.registry_identity_api_key = os.getenv("REGISTRY_IDENTITY_API_KEY")
        if not self.registry_identity_api_key:
            raise ValueError("REGISTRY_IDENTITY_API_KEY environment variable is not set")

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
headers = {"X-API-Key": settings.registry_identity_api_key}

registered_spk: List[Account] = []
reg_auth_challenges: List[AuthChallenge] = []

async def register_identity(id_value: int, id33_value: int, owner_id: uuid.UUID) -> int:
    url = urljoin(settings.registry_identity_url, "/identity/add")
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(
            url=url,
            params={"id_value": id_value, "id33_value": id33_value, "owner_id": owner_id},
            headers=headers
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
        return response.json()

async def get_all_active_ids(session) -> List[tuple[int, int]]:
    async with httpx.AsyncClient(verify=False) as client:
        size_response = await client.get(
            f"{REGISTRY_URL}/identity/size",
            headers={"X-API-Key": API_KEY}
        )
        size = size_response.json()
        
        active_ids = []
        for i in range(size):
            state_response = await client.get(
                f"{REGISTRY_URL}/identity/state/{i}",
                headers={"X-API-Key": API_KEY}
            )
            if state_response.json():
                id_response = await client.get(
                    f"{REGISTRY_URL}/identity/get/{i}",
                    headers={"X-API-Key": API_KEY}
                )
                active_ids.append(tuple(id_response.json()))
        return active_ids
    
@router.get("/servicename")
async def get_service_name() -> str:
    url = urljoin(settings.registry_identity_url, "identity/service")
    params = {"name": servicename_bytes}
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(url=url, headers=headers, params=params)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
    return servicename_bytes

@router.get("/challenge")
async def get_challenge(request: Request) -> bytes:
    ip_address = request.headers.get("X-Real-Ip")
    if not ip_address:
        ip_address = request.headers.get("X-Forwarded-For")
    if not ip_address:
        ip_address = request.client.host

    # Check if a challenge already exists for this IP address
    for auth_challenge in reg_auth_challenges:
        if auth_challenge.user_ip == ip_address:
            return auth_challenge.challenge

    # Create a new challenge if none exists for this IP address
    challenge = u2sso.create_challenge()
    hex_challenge = challenge.hex()
    reg_auth_challenges.append(AuthChallenge(challenge=hex_challenge, user_ip=ip_address))
    return hex_challenge

@router.post("/signup")
async def signup(
    request: Request,
    username: str,
    spk: str,
    nullifier: str,
    proof: str,
    ring_size: int
) -> Response:
    """Handle user signup with proof verification."""
    logger.info("======== SIGNUP REQUEST RECEIVED ========")
    
    try:
        spk_bytes = unhexlify(spk)
        nullifier_bytes = unhexlify(nullifier)
        ring_size = int(ring_size)

        # Compute `current_m`
        M = 10
        N = 2
        current_m = 1
        tmp = 1
        while current_m < M:
            tmp *= N
            if tmp >= ring_size:
                break
            current_m += 1

        # Get IP address from request headers
        ip_address = (
            request.headers.get("X-Real-Ip") or 
            request.headers.get("X-Forwarded-For") or 
            request.client.host
        )

        logger.info(f"Client IP Address: {ip_address}")

        # Find challenge for this IP
        challenge_bytes = None
        for auth_challenge in reg_auth_challenges:
            if auth_challenge.user_ip == ip_address:
                challenge_bytes = unhexlify(auth_challenge.challenge)
                break
        
        if not challenge_bytes:
            logger.warning("No challenge found for this IP")
            return Response(status_code=status.HTTP_400_BAD_REQUEST, content="No challenge found for this IP")
        
        service_name_bytes = unhexlify(servicename_bytes)

        with httpx.Client(verify=False) as client:
            # Fetch ID list
            response = client.get(urljoin(settings.registry_identity_url, "identity/ids"), headers=headers)
            id_list_bytes = [unhexlify(id_hex) for id_hex in response.json()]
            id_size = len(id_list_bytes)

            # Fetch topic list
            response = client.get(urljoin(settings.registry_identity_url, "identity/services"), headers=headers)
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to fetch services")
            topic_list = [unhexlify(topic) for topic in response.json()]
            topic_list_size = len(topic_list)

            # Get service index
            response = client.get(
                urljoin(settings.registry_identity_url, f"identity/service/{str(servicename_bytes)}/index"),
                headers=headers
            )
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to get service index")
            topic_index = response.json()
        

        # Run verification in an executor (non-blocking
        verified = u2sso.registration_verify(
            proof, current_m, id_size,
            service_name_bytes, challenge_bytes, id_list_bytes,
            spk_bytes, topic_list, topic_list_size, topic_index, nullifier_bytes
        )

        logger.info(f"Verification Result: {verified}")

        if not verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Proof verification failed"
            )
        
        account = Account(
            name=username,
            spk=spk_bytes,
            nullifier=nullifier_bytes,
            challenge=auth_challenge.challenge,
            user_ip=ip_address,
            registered=True,
            proof=proof
        )
        registered_spk.append(account)
        
        return Response(status_code=status.HTTP_200_OK, content="Signup successful")

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return Response(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=f"Invalid input: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return Response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content="Internal server error"
        )

@router.post("/login")
async def login(
    request: Request,
    username: str,
    spk: str,
    signature: str,
    challenge: str,
) -> Response:
    print("========login========")
    try:
        spk_bytes = unhexlify(spk)

        account = None
        for registered_account in registered_spk:
            if registered_account.name == username and registered_account.spk == spk_bytes:
                account = registered_account
                break
                
        if not account:
            return Response(content="Account not found", status_code=404)
        
        ip_address = request.headers.get("X-Real-Ip")
        if not ip_address:
            ip_address = request.headers.get("X-Forwarded-For")
        if not ip_address:
            ip_address = request.client.host
        
        for auth_challenge in reg_auth_challenges:
            if auth_challenge.user_ip == ip_address:
                challenge_bytes = unhexlify(auth_challenge.challenge)
                break
        
        with httpx.Client(verify=False) as client:
            # Get topic list
            response =  client.get(urljoin(settings.registry_identity_url, "identity/services"), headers=headers)
            if response.status_code != 200:
                print(f"Failed to fetch services: {response.status_code}")
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to fetch services")
            topic_list = [unhexlify(topic) for topic in response.json()]
            topic_list_size = len(topic_list)
        
        res = u2sso.auth_verify(
            signature,
            unhexlify(servicename_bytes),
            challenge_bytes,
            spk_bytes,
            topic_list,
            topic_list_size
        )
        if res:
            return Response(content="Login successful", status_code=200)
        else:
            return Response(content="Login failed", status_code=400)
    except Exception as e:
        print(e)
        return Response(content="Login failed", status_code=500)