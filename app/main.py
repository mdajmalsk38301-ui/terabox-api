import os
import re
import uuid
import asyncio
import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, HttpUrl, field_validator

APP_NAME = "TeraBox Video API"
VERSION = "1.0.0"
DOWNLOAD_DIR = Path(os.getenv("DOWNLOAD_DIR", "/app/downloads"))
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "2147483648"))
TERABOX_MODE = os.getenv("TERABOX_MODE", "auto").lower()
TERABOX_ACCESS_TOKEN = os.getenv("TERABOX_ACCESS_TOKEN", "")
TERABOX_NDUS = os.getenv("TERABOX_NDUS", "")
TERABOX_COOKIE = os.getenv("TERABOX_COOKIE", "")

DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_HOSTS = {
    "terabox.com",
    "www.terabox.com",
    "teraboxapp.com",
    "www.teraboxapp.com",
}

ALLOWED_EXTENSIONS = {
    ".mp4": "video/mp4",
    ".m4v": "video/x-m4v",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".mkv": "video/x-matroska",
    ".avi": "video/x-msvideo",
}

app = FastAPI(title=APP_NAME, version=VERSION)


class VideoRequest(BaseModel):
    url: HttpUrl

    @field_validator("url")
    @classmethod
    def validate_terabox_host(cls, value):
        host = (value.host or "").lower()
        if host not in ALLOWED_HOSTS and not host.endswith(".terabox.com"):
            raise ValueError("Only supported TeraBox URLs are accepted.")
        return value


def validate_safe_remote_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Invalid remote URL.")

    try:
        addresses = socket.getaddrinfo(parsed.hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise HTTPException(400, "Remote hostname cannot be resolved.")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise HTTPException(403, "Private/local remote addresses are blocked.")


def validate_share_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(400, "TeraBox URL must use HTTP or HTTPS.")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS and not host.endswith(".terabox.com"):
        raise HTTPException(400, "URL is not a supported TeraBox URL.")
    if not parsed.path or parsed.path == "/":
        raise HTTPException(400, "TeraBox URL has no share path.")


def cookie_header():
    parts = []
    if TERABOX_COOKIE.strip():
        parts.append(TERABOX_COOKIE.strip())
    if TERABOX_NDUS.strip() and "ndus=" not in TERABOX_COOKIE.lower():
        parts.append(f"ndus={TERABOX_NDUS.strip()}")
    return "; ".join(parts)


async def resolve_with_official_api(share_url: str):
    """
    Official-API integration point.

    TeraBox's OpenAPI contract and authorization details can change.
    Configure TERABOX_ACCESS_TOKEN and implement the exact current
    share/list or share/download request required by your TeraBox account.

    This function intentionally does not scrape private endpoints or
    bypass CAPTCHA, authentication, anti-bot controls, or access controls.
    """
    if not TERABOX_ACCESS_TOKEN:
        return None

    raise HTTPException(
        501,
        "Official TeraBox OpenAPI credentials are configured, but the current "
        "OpenAPI resolver has not been configured for this deployment."
    )


async def resolve_with_authorized_cookie(share_url: str):
    """
    Cookie-mode integration point.

    A server-side TeraBox session may be supplied through TERABOX_COOKIE
    and/or TERABOX_NDUS. This function is intentionally a safe integration
    point and does not attempt to bypass login, CAPTCHA, or anti-bot controls.

    Return format when your authorized resolver is connected:
      {
        "download_url": "...",
        "filename": "video.mp4",
        "content_type": "video/mp4"
      }
    """
    if not cookie_header():
        return None

    raise HTTPException(
        501,
        "Cookie credentials are configured, but the authorized TeraBox "
        "resolver has not been configured for this deployment."
    )


async def resolve_terabox_url(share_url: str):
    validate_share_url(share_url)

    if TERABOX_MODE not in {"auto", "api", "cookie"}:
        raise HTTPException(500, "TERABOX_MODE must be auto, api, or cookie.")

    if TERABOX_MODE in {"auto", "api"}:
        result = await resolve_with_official_api(share_url)
        if result:
            return result

    if TERABOX_MODE in {"auto", "cookie"}:
        result = await resolve_with_authorized_cookie(share_url)
        if result:
            return result

    raise HTTPException(
        501,
        "No TeraBox resolver is configured. Add an authorized OpenAPI "
        "integration or an authorized session resolver."
    )


def safe_filename(name: str):
    name = os.path.basename(name or "video.mp4")
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip()
    return (name or "video.mp4")[:200]


async def download_file(url: str, path: Path):
    validate_safe_remote_url(url)

    headers = {"User-Agent": "TeraBox-Video-API/1.0"}

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(connect=20, read=60, write=60, pool=30),
            headers=headers,
        ) as client:
            async with client.stream("GET", url) as response:
                if response.status_code >= 400:
                    raise HTTPException(502, f"Remote server returned HTTP {response.status_code}.")

                length = response.headers.get("content-length")
                if length and int(length) > MAX_FILE_SIZE:
                    raise HTTPException(413, "Video exceeds the configured size limit.")

                total = 0
                with path.open("wb") as output:
                    async for chunk in response.aiter_bytes(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_FILE_SIZE:
                            output.close()
                            path.unlink(missing_ok=True)
                            raise HTTPException(413, "Video exceeds the configured size limit.")
                        output.write(chunk)

                return total

    except httpx.TimeoutException:
        path.unlink(missing_ok=True)
        raise HTTPException(504, "Timed out while downloading the video.")
    except httpx.RequestError as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(502, f"Remote download failed: {exc}")


def locate_video(video_id: str):
    if not re.fullmatch(r"[a-f0-9]{32}", video_id):
        raise HTTPException(400, "Invalid video ID.")
    matches = list(DOWNLOAD_DIR.glob(f"{video_id}.*"))
    if not matches:
        raise HTTPException(404, "Video not found or expired.")
    return matches[0]


@app.get("/health")
async def health():
    return {"status": "ok", "service": APP_NAME, "version": VERSION}


@app.post("/api/v1/terabox/download")
async def create_download(payload: VideoRequest, request: Request):
    share_url = str(payload.url)
    resolved = await resolve_terabox_url(share_url)

    direct_url = resolved.get("download_url")
    if not direct_url:
        raise HTTPException(502, "Resolver did not return a direct media URL.")

    filename = safe_filename(resolved.get("filename", "video.mp4"))
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(415, "Unsupported video format.")

    video_id = uuid.uuid4().hex
    output = DOWNLOAD_DIR / f"{video_id}{extension}"

    size = await download_file(direct_url, output)

    base = str(request.base_url).rstrip("/")
    return {
        "id": video_id,
        "status": "ready",
        "filename": filename,
        "size": size,
        "download_url": f"{base}/api/v1/terabox/{video_id}/download",
        "stream_url": f"{base}/api/v1/terabox/{video_id}/stream",
    }


@app.get("/api/v1/terabox/{video_id}")
async def metadata(video_id: str):
    path = locate_video(video_id)
    return {
        "id": video_id,
        "filename": path.name,
        "size": path.stat().st_size,
        "stream_url": f"/api/v1/terabox/{video_id}/stream",
        "download_url": f"/api/v1/terabox/{video_id}/download",
    }


@app.get("/api/v1/terabox/{video_id}/download")
async def download(video_id: str):
    path = locate_video(video_id)
    media_type = ALLOWED_EXTENSIONS.get(path.suffix.lower(), "application/octet-stream")
    return FileResponse(path, media_type=media_type, filename=path.name)


@app.get("/api/v1/terabox/{video_id}/stream")
async def stream(video_id: str, request: Request):
    path = locate_video(video_id)
    size = path.stat().st_size
    media_type = ALLOWED_EXTENSIONS.get(path.suffix.lower(), "application/octet-stream")
    range_header = request.headers.get("range")

    if not range_header:
        return FileResponse(
            path,
            media_type=media_type,
            headers={"Accept-Ranges": "bytes", "Content-Length": str(size)},
        )

    match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header)
    if not match:
        raise HTTPException(416, "Invalid Range header.")

    start_s, end_s = match.groups()
    if start_s:
        start = int(start_s)
    else:
        suffix = int(end_s)
        start = max(size - suffix, 0)

    end = int(end_s) if end_s else size - 1
    end = min(end, size - 1)

    if start >= size or start > end:
        raise HTTPException(416, "Requested range is not satisfiable.")

    length = end - start + 1

    async def iterator():
        with path.open("rb") as f:
            f.seek(start)
            remaining = length
            while remaining:
                chunk = f.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    return StreamingResponse(
        iterator(),
        status_code=206,
        media_type=media_type,
        headers={
            "Accept-Ranges": "bytes",
            "Content-Range": f"bytes {start}-{end}/{size}",
            "Content-Length": str(length),
        },
    )


@app.delete("/api/v1/terabox/{video_id}")
async def delete(video_id: str):
    path = locate_video(video_id)
    path.unlink(missing_ok=True)
    return {"id": video_id, "status": "deleted"}


async def cleanup_loop():
    while True:
        now = os.path.getmtime
        # Keep cleanup conservative. Files older than one hour are removed.
        ttl = int(os.getenv("FILE_TTL", "3600"))
        import time
        current = time.time()
        for path in DOWNLOAD_DIR.iterdir():
            if path.is_file():
                try:
                    if current - path.stat().st_mtime > ttl:
                        path.unlink()
                except OSError:
                    pass
        await asyncio.sleep(900)


@app.on_event("startup")
async def startup():
    asyncio.create_task(cleanup_loop())
