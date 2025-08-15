from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from .database import Base

class Packet(Base):
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(128), index=True)
    dst_ip = Column(String(128), index=True)
    protocol = Column(String(32))
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    length = Column(Integer, nullable=True)
    info = Column(String(256), nullable=True)

class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(64))
    src_ip = Column(String(128), index=True)
    details = Column(String(512))
    ts = Column(DateTime, default=datetime.utcnow, index=True)
