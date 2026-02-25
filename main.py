# main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from auth import router as auth_router
from proxy_service import router as proxy_router

app = FastAPI(
    title="ProxySocket API",
    version="1.0.0",
    description="Backend for ProxySocket iOS app"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/auth", tags=["Auth"])
app.include_router(proxy_router, prefix="/api/proxies", tags=["Proxies"])


@app.get("/")
async def root():
    return {"status": "ok", "service": "ProxySocket API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
