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

TAG = "U2SSO"

router = fastapi.APIRouter(tags=[TAG])

_logger = logging.getLogger(__name__)

REGISTRY_URL = "https://registry_identity"
API_KEY = "tergum_dev_key"

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

registered_spk: List[Account] = []
reg_auth_challenges: List[AuthChallenge] = []

async def register_identity(id_value: int, id33_value: int, owner_id: uuid.UUID) -> int:
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(
            f"{REGISTRY_URL}/identity/add",
            params={"id_value": id_value, "id33_value": id33_value, "owner_id": owner_id},
            headers={"X-API-Key": API_KEY}
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

@router.post("/signup")
async def signup(
    request: Request,
    name: str = Form(...),
    challenge: str = Form(...),
    spk: str = Form(...),
    nullifier: str = Form(...),
    proof: str = Form(...),
    n: int = Form(...)
) -> Response:
    try:
        challenge_bytes = bytes.fromhex(challenge)
        spk_bytes = bytes.fromhex(spk)
        nullifier_bytes = bytes.fromhex(nullifier)
        
        id_list = await get_all_active_ids(None)
        
        current_m = next(m for m in range(1, u2sso.M) 
                      if pow(u2sso.N, m) >= n)
        
        if u2sso.registration_verify(proof, current_m, n, challenge_bytes, id_list, spk_bytes):
            owner_id = uuid.uuid4()
            index = await register_identity(int.from_bytes(spk_bytes, 'big'), 
                                         int.from_bytes(nullifier_bytes, 'big'),
                                         owner_id)
            
            for acc in registered_spk:
                if acc.challenge == challenge_bytes:
                    acc.name = name
                    acc.spk = spk_bytes
                    acc.nullifier = nullifier_bytes
                    acc.proof = proof
                    acc.registered = True
            
            with open("./static/registration_success.html") as f:
                html = f.read()
            return HTMLResponse(content=html.replace("{{NAME}}", name))
        
        with open("./static/registration_fail.html") as f:
            return HTMLResponse(content=f.read())
            
    except Exception as e:
        _logger.error(f"Signup failed: {e}")
        return Response(content="Registration failed", status_code=500)

@router.post("/login")
async def login(
    request: Request,
    name: str = Form(...),
    challenge: str = Form(...),
    spk: str = Form(...),
    signature: str = Form(...)
) -> Response:
    try:
        challenge_bytes = bytes.fromhex(challenge)
        spk_bytes = bytes.fromhex(spk)
        
        index = await httpx.AsyncClient(verify=False).get(
            f"{REGISTRY_URL}/identity/find",
            params={"id_value": int.from_bytes(spk_bytes, 'big')},
            headers={"X-API-Key": API_KEY}
        )
        
        if index == -1:
            return HTMLResponse(content=open("./static/login_fail.html").read())
            
        is_active = await httpx.AsyncClient(verify=False).get(
            f"{REGISTRY_URL}/identity/state/{index}",
            headers={"X-API-Key": API_KEY}
        )
        
        if not is_active:
            return HTMLResponse(content=open("./static/login_fail.html").read())
            
        if u2sso.auth_verify(signature, challenge_bytes, spk_bytes):
            with open("./static/login_success.html") as f:
                html = f.read()
            return HTMLResponse(content=html.replace("{{NAME}}", name))
            
        return HTMLResponse(content=open("./static/login_fail.html").read())
            
    except Exception as e:
        _logger.error(f"Login failed: {e}")
        return Response(content="Login failed", status_code=500)