# Employee Management Backend

Python HTTP API with role-based authentication and SQLite storage.

## Local development

Python 3 is required. This backend uses only Python standard-library modules.

```powershell
python server.py
```

The server runs at `http://127.0.0.1:8000` by default.

Run the test suite with:

```powershell
python -m unittest test_auth.py
```

## Render deployment

Create a Render Web Service from the repository and configure:

| Setting | Value |
| --- | --- |
| Runtime | Python 3 |
| Root Directory | `be` |
| Build Command | Leave empty |
| Start Command | `python server.py` |
| Health Check Path | `/api/auth/status` |

Add these Render environment variables:

```dotenv
HOST=0.0.0.0
FRONTEND_ORIGIN=https://your-project.vercel.app
COOKIE_SECURE=1
ENABLE_DEMO_LOGIN=0
```

Render provides `PORT` automatically. `FRONTEND_ORIGIN` must be the exact Vercel production origin without a trailing slash.

## SQLite persistence

Render's normal filesystem is ephemeral. For persistent data, use a paid service, attach a disk at `/var/data`, and add:

```dotenv
DATABASE_PATH=/var/data/users.sqlite3
```

For a temporary free deployment, omit `DATABASE_PATH`. The default database can be lost when Render restarts or redeploys the service.

After deployment, verify the API at:

```text
https://your-api-service.onrender.com/api/auth/status
```
