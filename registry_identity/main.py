import uuid
from fastapi import APIRouter, HTTPException, Security, status, Header
from sqlalchemy.sql.expression import select
from sqlalchemy.exc import SQLAlchemyError

import common.db.postgres as db
from common.apikey import require_api_key
from common.fastapi_extensions import ExtendedFastAPI
from common.health import HealthAPIRouterWithDBInject

from registry_identity.models import Identity, Service
import registry_identity.config as conf
import logging
from binascii import unhexlify, hexlify



_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)

app = ExtendedFastAPI(conf.inject)
router = APIRouter(prefix="/identity")



@router.post("/add")
async def add_identity(id_bytes: str, owner_id: str, session: db.inject) -> int:
    """Add a new identity"""
    try:
        # Convert hex string to bytes
        id_bytes_raw = unhexlify(id_bytes)
        
        identity = Identity(
            id_value=id_bytes_raw[:32],
            id33_value=id_bytes_raw[32:],
            active=True,
            owner_id=uuid.UUID(owner_id)
        )
        print(f"Creating identity with ID: {id_bytes}")
        session.add(identity)
        session.flush()
        session.commit()
        return identity.index
    except Exception as e:
        print(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

    
@router.post("/revoke/{index}")
async def revoke_identity(index: int, owner_id: uuid.UUID, session: db.inject):
    """Revoke an identity if caller is the owner"""
    identity = session.get(Identity, index)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    
    if identity.owner_id != owner_id:
        raise HTTPException(status_code=403, detail="Not authorized to revoke this identity")
    
    identity.active = False
    session.commit()

@router.get("/get/{index}")
async def get_identity(index: int, session: db.inject) -> tuple[int, int]:
    """Get the ID values for a given index"""
    identity = session.get(Identity, index)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return (identity.id_value, identity.id33_value)

@router.get("/state/{index}")
async def get_identity_state(index: int, session: db.inject) -> bool:
    """Get the active state of an identity"""
    identity = session.get(Identity, index)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity.active

@router.get("/size")
async def get_identity_size(session: db.inject) -> int:
    """Get total number of identities"""
    return session.query(Identity).count()

@router.get("/find")
async def get_identity_index(id_bytes: str, session: db.inject) -> int:
    """Find identity index by ID"""
    try:
        # Convert hex string to bytes
        id_bytes_raw = unhexlify(id_bytes)
        
        print(f"Looking for ID: {id_bytes}")
        print(f"ID bytes length: {len(id_bytes_raw)}")
        
        # Log all identities for debugging
        all_ids = session.query(Identity).all()
        print("All identities in database:")
        for identity in all_ids:
            full_id = identity.id_value + identity.id33_value
            print(f"Index {identity.index}: {hexlify(full_id).decode()}")
            print(f"Active: {identity.active}")
        
        # Perform the lookup
        result = session.execute(
            select(Identity.index)
            .where(Identity.id_value == id_bytes_raw[:32])
            .where(Identity.id33_value == id_bytes_raw[32:])
            .where(Identity.active == True)  # Only look for active identities
        ).first()
        
        if not result:
            _logger.warning(f"No matching identity found for ID: {id_bytes}")
            return -1
            
        print(f"Found identity at index: {result[0]}")
        return result[0]
        
    except Exception as e:
        _logger.error(f"Error in get_identity_index: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
        
    except Exception as e:
        _logger.error(f"Error in get_identity_index: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/ids")
async def get_all_identities(session: db.inject) -> list[str]:
    """Get all active identities as hex strings"""
    try:
        identities = session.query(Identity).filter(Identity.active == True).all()
        
        id_list = []
        for identity in identities:
            combined_id = identity.id_value + identity.id33_value
            id_list.append(hexlify(combined_id).decode())
            
        print(f"Found {len(id_list)} active identities")
        for i, id_hex in enumerate(id_list):
            print(f"Identity {i}: {id_hex}")
            
        return id_list
        
    except Exception as e:
        _logger.error(f"Error getting identities: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/service")
async def register_service(name: str, session: db.inject):
    """Register a new service if limit not reached"""
    try:
        # Add service count check
        service_count = session.query(Service).count()
        if service_count >= 4:  # Match Solidity contract's limit
            raise HTTPException(
                status_code=400, 
                detail="Service list is full (max 4 services)"
            )
            
        service = Service(name=name)
        session.add(service)
        session.commit()
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Failed to register service")

@router.get("/services")
async def get_all_services(session: db.inject) -> list[str]:
    """Get all registered services"""
    services = session.query(Service.name).all()
    return [service[0] for service in services]

@router.get("/service/{service_name}/index")
async def get_service_index(service_name: str, session: db.inject) -> int:
    """Get index of a service by name"""
    try:
        # Log incoming request
        print(f"Getting service index for: {service_name}")
        
        # Query and log all services for debugging
        all_services = session.query(Service).all()
        print("Available services:")
        for svc in all_services:
            print(f"  Index {svc.index}: {svc.name}")
        
        # Query the specific service
        service = session.query(Service).filter(Service.name == service_name).first()
        print(f"Query result for {service_name}: {service}")
        
        if not service:
            _logger.warning(f"Service not found: {service_name}")
            return -1
            
        result = service.index - 1
        print(f"Returning index: {result}")
        return int(result)
        
    except Exception as e:
        print(f"Error getting service index: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving service index: {str(e)}"
        )
    finally:
        session.close()


app.include_router(router)