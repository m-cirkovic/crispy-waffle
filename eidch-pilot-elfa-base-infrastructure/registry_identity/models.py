from sqlalchemy import Column, BigInteger, Boolean, Integer, String
from sqlalchemy.dialects.postgresql import UUID, BYTEA
import common.db.postgres as db

class Identity(db.Base):
    __tablename__ = "identity"
    __table_args__ = {'schema': 'public'}  # Explicitly set schema
    
    index = Column(BigInteger, primary_key=True, autoincrement=True)
    id_value = Column(BYTEA, nullable=False)
    id33_value = Column(BYTEA, nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    owner_id = Column(UUID(as_uuid=True), nullable=False)

class Service(db.Base):
    __tablename__ = "service"
    __table_args__ = {'schema': 'public'}  # Explicitly set schema
    
    index = Column(Integer, primary_key=True, autoincrement=True)  
    name = Column(String, nullable=False, unique=True)