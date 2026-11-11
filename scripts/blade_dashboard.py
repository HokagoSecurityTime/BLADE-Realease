#!/usr/bin/env python
"""BLADE 대시보드(정적) 서버 — 전시 노트북용.

Node 없이 미리 빌드된 React 대시보드(dashboard_dist/)를 띄우고,
`/api/*` 요청만 admin-api(:8100)로 넘긴다(개발용 vite proxy와 같은 동작: /api 접두 제거).

    python scripts/blade_dashboard.py          # http://127.0.0.1:3000

환경변수:
    BLADE_DASHBOARD_PORT  기본 3000
    BLADE_DASHBOARD_HOST  기본 127.0.0.1 (QR·외부 노출 시 0.0.0.0)
    BLADE_ADMIN_URL       기본 http://127.0.0.1:8100

admin 이 아직 안 떠 있으면(vuln 구간) /api 는 502 를 돌려주고, 화면은 "연결 중"으로
표시하며 5초마다 다시 시도한다. apply 로 admin 이 뜨면 자동으로 채워진다.
런타임 코드(proxy/·admin_api/)는 건드리지 않는다.
"""
import os
import sys
from pathlib import Path

try:
    import aiohttp
    from aiohttp import web
except ImportError:
    sys.exit("aiohttp 가 없습니다. 데모 저장소를 'pip install -e .' 로 설치하면 BLADE 와 함께 깔립니다.")

ROOT = Path(__file__).resolve().parent.parent
DIST = (ROOT / "dashboard_dist").resolve()
ADMIN = os.environ.get("BLADE_ADMIN_URL", "http://127.0.0.1:8100").rstrip("/")
HOST = os.environ.get("BLADE_DASHBOARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("BLADE_DASHBOARD_PORT", "3000"))

_HOP = {"host", "content-length", "transfer-encoding", "connection", "keep-alive"}


async def proxy(request: web.Request) -> web.Response:
    tail = request.match_info["tail"]
    url = f"{ADMIN}/{tail}"
    body = await request.read()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                request.method, url,
                params=request.rel_url.query,
                data=body or None,
                headers=headers,
                allow_redirects=False,
            ) as upstream:
                raw = await upstream.read()
                resp = web.Response(status=upstream.status, body=raw)
                ctype = upstream.headers.get("Content-Type")
                if ctype:
                    resp.headers["Content-Type"] = ctype
                return resp
    except aiohttp.ClientError:
        return web.json_response(
            {"detail": "admin-api(:8100)에 연결할 수 없습니다. apply 상태인지 확인하세요."},
            status=502,
        )


async def static(request: web.Request) -> web.FileResponse:
    rel = request.path.lstrip("/") or "index.html"
    target = (DIST / rel).resolve()
    if DIST == target or DIST in target.parents:
        if target.is_file():
            return web.FileResponse(target)
    return web.FileResponse(DIST / "index.html")  # SPA fallback


def main() -> None:
    if not (DIST / "index.html").is_file():
        sys.exit(f"대시보드 빌드가 없습니다: {DIST}\\index.html (저장소에 dashboard_dist/ 가 포함돼야 합니다)")
    app = web.Application()
    app.router.add_route("*", "/api/{tail:.*}", proxy)
    app.router.add_route("GET", "/{tail:.*}", static)
    print(f"[blade-dashboard] http://{HOST}:{PORT}  → admin {ADMIN}  (dist: {DIST})")
    print("  Ctrl+C 로 종료. apply 상태에서 정책·탐지·차단 로그가 보입니다.")
    web.run_app(app, host=HOST, port=PORT, print=None)


if __name__ == "__main__":
    main()
