import uuid
import logging
from fastapi import APIRouter, HTTPException, Security, status
from asgi_correlation_id import CorrelationIdMiddleware
from sqlalchemy.sql.expression import select
from sqlalchemy.exc import SQLAlchemyError

import common.db.postgres as db
from common.apikey import require_api_key
from common.fastapi_extensions import ExtendedFastAPI
from common.health import HealthAPIRouterWithDBInject

from registry_identity.models import Identity
import registry_identity.config as conf

_logger = logging.getLogger(__name__)

app = ExtendedFastAPI(conf.inject)
app.add_middleware(CorrelationIdMiddleware)

# Main router for identity operations
router = APIRouter(prefix="/identity")

@router.post("/add", response_model=int)
async def add_identity(id_value: int, id33_value: int, owner_id: uuid.UUID, session: db.inject) -> int:
    """Add a new identity to the registry"""
    try:
        identity = Identity(
            id_value=id_value,
            id33_value=id33_value,
            active=True,
            owner_id=owner_id
        )
        session.add(identity)
        session.flush()  # To get the index
        session.commit()
        return identity.index
    except SQLAlchemyError as e:
        _logger.error(f"Database error adding identity: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                          detail="Failed to add identity")

@router.post("/revoke/{index}")
async def revoke_identity(index: int, owner_id: uuid.UUID, session: db.inject):
    """Revoke an identity if caller is the owner"""
    identity = session.get(Identity, index)
    if not identity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                          detail="Identity not found")
    
    if identity.owner_id != owner_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                          detail="Not authorized to revoke this identity")
    
    identity.active = False
    session.commit()

@router.get("/get/{index}")
async def get_identity(index: int, session: db.inject) -> tuple[int, int]:
    """Get the ID values for a given index"""
    identity = session.get(Identity, index)
    if not identity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                          detail="Identity not found")
    return (identity.id_value, identity.id33_value)

@router.get("/state/{index}")
async def get_identity_state(index: int, session: db.inject) -> bool:
    """Get the active state of an identity"""
    identity = session.get(Identity, index)
    if not identity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                          detail="Identity not found")
    return identity.active

@router.get("/size")
async def get_identity_size(session: db.inject) -> int:
    """Get total number of identities"""
    return session.query(Identity).count()

@router.get("/find")
async def get_identity_index(id_value: int, id33_value: int, session: db.inject) -> int:
    """Find the index of an identity by its ID values"""
    result = session.execute(
        select(Identity.index)
        .where(Identity.id_value == id_value)
        .where(Identity.id33_value == id33_value)
    ).first()
    
    return result[0] if result else -1

app.include_router(router)
app.include_router(HealthAPIRouterWithDBInject())