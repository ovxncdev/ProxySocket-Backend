# proxy_service.py

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from auth import get_session, NINE_PROXY_BASE
import httpx

router = APIRouter()


class ProxyItem(BaseModel):
    id: str
    host: str
    port: int = 0
    username: str = ""
    password: str = ""
    protocol_type: str = "SOCKS5"
    country_code: str = ""
    city: str = ""
    ip: str = ""
    is_online: bool = False


class ProxyListResponse(BaseModel):
    proxies: list[ProxyItem]
    total: int


class ForwardRequest(BaseModel):
    proxy_id: str
    port: int


class ForwardResponse(BaseModel):
    host: str
    port: int
    username: str
    password: str
    protocol_type: str
    message: str


class PortStatusItem(BaseModel):
    address: str = ""
    city: str = ""
    public_ip: str = ""
    online: bool = False


@router.get("/today", response_model=ProxyListResponse)
async def get_today_list(
    country: str = "",
    city: str = "",
    isp: str = "",
    limit: int = 50,
    authorization: str = Header(default="")
):
    """
    Fetch today's available proxies from 9Proxy.
    Maps to: GET /api/today_list
    """
    token = authorization.replace("Bearer ", "")
    session = get_session(token)

    try:
        proxies = await fetch_today_list(
            cookies=session["cookies"],
            headers=session["headers"],
            country=country,
            city=city,
            isp=isp,
            limit=limit,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return ProxyListResponse(
        proxies=proxies,
        total=len(proxies)
    )


@router.post("/forward", response_model=ForwardResponse)
async def forward_proxy(
    request: ForwardRequest,
    authorization: str = Header(default="")
):
    """
    Forward/activate a proxy to a specific port.
    Maps to: GET /api/forward
    """
    token = authorization.replace("Bearer ", "")
    session = get_session(token)

    try:
        result = await forward_to_port(
            cookies=session["cookies"],
            headers=session["headers"],
            proxy_id=request.proxy_id,
            port=request.port,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return result


@router.get("/ports", response_model=list[PortStatusItem])
async def get_port_status(
    authorization: str = Header(default="")
):
    """
    Check status of all forwarded ports.
    Maps to: GET /api/port_status
    """
    token = authorization.replace("Bearer ", "")
    session = get_session(token)

    try:
        ports = await fetch_port_status(
            cookies=session["cookies"],
            headers=session["headers"],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return ports


async def fetch_today_list(
    cookies: dict,
    headers: dict,
    country: str = "",
    city: str = "",
    isp: str = "",
    limit: int = 50,
) -> list[ProxyItem]:
    """
    GET /api/today_list
    Response: {
        "error": false,
        "message": "...",
        "data": [
            {
                "id": "text",
                "city": "text",
                "ip": "text",
                "country_code": "text",
                "is_online": true,
                "binding": null
            }
        ]
    }
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        params = {"t": "2", "limit": str(limit)}
        if country:
            params["country"] = country
        if city:
            params["city"] = city
        if isp:
            params["isp"] = isp

        response = await client.get(
            f"{NINE_PROXY_BASE}/api/today_list",
            params=params,
            cookies=cookies,
            headers=headers,
        )

        if response.status_code != 200:
            raise Exception(
                f"9Proxy returned status {response.status_code}"
            )

        data = response.json()

        if data.get("error"):
            raise Exception(data.get("message", "Unknown error"))

        proxies = []
        for item in data.get("data", []):
            proxy = ProxyItem(
                id=item.get("id", ""),
                host=item.get("ip", ""),
                ip=item.get("ip", ""),
                country_code=item.get("country_code", ""),
                city=item.get("city", ""),
                is_online=item.get("is_online", False),
            )
            proxies.append(proxy)

        return proxies


async def forward_to_port(
    cookies: dict,
    headers: dict,
    proxy_id: str,
    port: int,
) -> ForwardResponse:
    """
    GET /api/forward?id={proxy_id}&port={port}&t=2
    Activates a proxy and binds it to a port.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        params = {
            "id": proxy_id,
            "port": str(port),
            "t": "2",
        }

        response = await client.get(
            f"{NINE_PROXY_BASE}/api/forward",
            params=params,
            cookies=cookies,
            headers=headers,
        )

        if response.status_code != 200:
            raise Exception(
                f"Forward failed with status {response.status_code}"
            )

        data = response.json()

        if data.get("error"):
            raise Exception(data.get("message", "Forward failed"))

        # After forwarding, the proxy is available at
        # the server's IP on the specified port
        return ForwardResponse(
            host="127.0.0.1",
            port=port,
            username="",
            password="",
            protocol_type="SOCKS5",
            message=data.get("message", "Proxy forwarded successfully")
        )


async def fetch_port_status(
    cookies: dict,
    headers: dict,
) -> list[PortStatusItem]:
    """
    GET /api/port_status?t=2
    Response: {
        "error": false,
        "data": [
            {
                "address": "text",
                "city": "text",
                "public_ip": "text",
                "online": true
            }
        ]
    }
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{NINE_PROXY_BASE}/api/port_status",
            params={"t": "2"},
            cookies=cookies,
            headers=headers,
        )

        if response.status_code != 200:
            return []

        data = response.json()

        if data.get("error"):
            return []

        ports = []
        for item in data.get("data", []):
            port = PortStatusItem(
                address=item.get("address", ""),
                city=item.get("city", ""),
                public_ip=item.get("public_ip", ""),
                online=item.get("online", False),
            )
            ports.append(port)

        return ports
