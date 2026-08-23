# TeraBox Video API

FastAPI service for an authorized TeraBox integration.

## Important

This repository does **not** bypass TeraBox authentication, CAPTCHA,
anti-bot controls, paywalls, or access restrictions.

The two resolver functions in `app/main.py` are integration points:

- `resolve_with_official_api()`
- `resolve_with_authorized_cookie()`

Connect them to an authorized TeraBox API/session mechanism before expecting
`POST /api/v1/terabox/download` to resolve a share URL.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

- http://127.0.0.1:8000/health
- http://127.0.0.1:8000/docs

## Docker

```bash
docker build -t terabox-api .
docker run -p 8000:8000 --env-file .env terabox-api
```

## Render

This repository includes `render.yaml`.

1. Push the repository to GitHub.
2. In Render choose New -> Blueprint.
3. Select the repository.
4. Add secret environment variables in Render.
5. Deploy.

Do not commit `.env` or real cookies/tokens.

## API

### Health

`GET /health`

### Create download

`POST /api/v1/terabox/download`

```json
{
  "url": "https://www.terabox.com/s/example"
}
```

### Metadata

`GET /api/v1/terabox/{id}`

### Stream

`GET /api/v1/terabox/{id}/stream`

Supports HTTP Range requests for seeking.

### Download

`GET /api/v1/terabox/{id}/download`

### Delete

`DELETE /api/v1/terabox/{id}`

## Environment variables

```text
TERABOX_MODE=auto
TERABOX_ACCESS_TOKEN=
TERABOX_NDUS=
TERABOX_COOKIE=
MAX_FILE_SIZE=2147483648
DOWNLOAD_DIR=/app/downloads
FILE_TTL=3600
```

Treat cookies and access tokens as secrets.
