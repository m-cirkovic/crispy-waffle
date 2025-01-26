from fastapi import APIRouter, HTTPException, status, Depends
from typing import List, Optional

from common import key_configuration as key
from wallet import config as conf
from common.u2sso import u2sso
import requests
import random
import uuid

router = APIRouter(tags=["U2SSO"])


@router.get("/hello")
async def hello():
   """List stored credentials with optional filtering"""
   return "hello"

@router.post("/create_passkey")
async def create_passkey(
    key_name: str
):
    """Create a passkey for a user"""
    passkey = u2sso.create_passkey(key_name)
    return {"passkey": passkey}

@router.post("/load_passkey")
async def load_passkey(
    load_passkey: str
):
    """Load a passkey for a user"""
    passkey, succes = u2sso.load_passkey(load_passkey)
    return {"passkey": passkey.hex()} 

@router.post("/register")
async def register(
    passkey: str,
    service_name: str,
    challenge: str
):
    """Register a passkey for a user"""
    passkey = bytes.fromhex(passkey)
    challenge = bytes.fromhex(challenge)
    service_name = bytes.fromhex(service_name)
    
    try:
        url = "https://registry_identity:443/size"
        response = requests.get(url)
        print(response.text)
    except Exception as e:
        print(e)
    return "hey"

@router.post("/create_identity")
async def create_identity():
    try:
        url = "http://registry_identity/identity/add"
        data = {
            "id_value": random.randint(1, 1000),
            "id33_value": random.randint(1, 1000), 
            "owner_id": str(uuid.uuid4())
        }
        response = requests.post(url, json=data)
        return {"index": response.json()}
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=str(e))