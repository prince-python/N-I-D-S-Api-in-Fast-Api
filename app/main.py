from fastapi import FastAPI
from .database import engine, Base
from  .models import *
from .routes import router
from .capture import SnifferThread
from .config import IFACE, BPF_FILTER

app = FastAPI(title="NIDS Backend")

app.include_router(router, prefix="/api")

@app.on_event("startup")
def startup_event():
    # create tables
    Base.metadata.create_all(bind=engine)
    # start sniffer thread
    sn = SnifferThread(iface=IFACE, bpf=BPF_FILTER)
    sn.start()

@app.get("/")
def root():
    return {"message": "NIDS Backend running"}
