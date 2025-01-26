import uuid
from sqlalchemy import Column, BigInteger, Boolean
from sqlalchemy.dialects.postgresql import UUID
import common.db.postgres as db

class Identity(db.Base):
    __tablename__ = "identity"
    
    # Internal auto-incrementing index
    index = Column(BigInteger, primary_key=True, autoincrement=True)
    
    # The actual identity values
    id_value = Column(BigInteger, nullable=False)
    id33_value = Column(BigInteger, nullable=False)
    
    # State/ownership tracking
    active = Column(Boolean, nullable=False, default=True)
    owner_id = Column(UUID(as_uuid=True), nullable=False)