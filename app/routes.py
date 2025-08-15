from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Packet, Detection
from typing import List

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/packets")
def get_packets(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    rows = db.query(Packet).order_by(Packet.id.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "ts": r.ts.isoformat(),
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "protocol": r.protocol,
            "src_port": r.src_port,
            "dst_port": r.dst_port,
            "length": r.length,
            "info": r.info,
        } for r in rows
    ]

@router.get("/detections")
def get_detections(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    rows = db.query(Detection).order_by(Detection.id.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "ts": r.ts.isoformat(),
            "alert_type": r.alert_type,
            "src_ip": r.src_ip,
            "details": r.details
        } for r in rows
    ]
