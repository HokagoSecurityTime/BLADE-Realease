# BLADE — 런타임 인가 프록시

내 API 앞에 BLADE를 세우면 엔드포인트별 **인가 정책**을 집행해 **BOLA/IDOR**(남의 리소스 조회·수정) 공격을 차단합니다. 애플리케이션 코드는 고치지 않습니다.

```
호출자 ──JWT──▶ [ BLADE 프록시 :8080 ] ──허용──▶ 내 API(업스트림)
                     │  1) JWT 검증 (BLADE_JWT_SECRET)
                     │  2) 경로 → ACTIVE 정책 매칭
                     │  3) 객체형 정책이면 내 DB에서 소유자/테넌트 조회해 호출자와 비교
                     └─ 차단 ▶ 403 + 탐지 로그 ▶ admin :8100 ▶ 대시보드 :3000
```

> 이 저장소는 런타임 엔진만 담은 배포본입니다(프록시·admin·분류기). 데이터셋·학습·실험 보고서는 포함하지 않습니다.

---

## 1. 처음 넣는 설정값

`.env.example`를 `.env`로 복사해 아래 값을 채웁니다. **비밀값은 커밋·화면에 노출하지 마세요.**

### 꼭 필요한 값

| 변수 | 기본값 | 설명 |
|---|---|---|
| `BLADE_JWT_SECRET` | (없음) | 호출자 JWT를 검증하는 HMAC 시크릿. 토큰 발급 측과 **같은 값**(32바이트 이상). |
| `BLADE_TARGET_URL` | `http://127.0.0.1:9000` | BLADE가 보호할 **내 API** 주소(업스트림). |
| `BLADE_DB_DSN` | `sqlite:///demo.db` | 소유자/테넌트 조회용 **내 DB 읽기 전용 DSN**. `owner_match`·`tenant_match`·`owner_or_admin` 정책에 필요. |

### 분류기 — 정책을 무엇으로 만들까

| 변수 | 기본값 | 설명 |
|---|---|---|
| `BLADE_CLASSIFIER` | `llm` | `llm` 또는 `lora`. lora 실패 시 llm으로 폴백. |
| `BLADE_LLM_PROVIDER` | (없음) | `llm`일 때: `openai` \| `anthropic` \| `ollama`. |
| `BLADE_LLM_MODEL` | (없음) | 제공자 모델 이름, 예 `gpt-4o-mini`. |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | (없음) | 클라우드 제공자일 때만. |
| `BLADE_LORA_MODEL` | `blade-qwen-lora-v4` | `lora`일 때 Ollama에 등록한 모델(우리 릴리스는 `blade-qwen-lora-v7`). |
| `BLADE_OLLAMA_URL` | `http://127.0.0.1:11434` | 로컬 Ollama 주소. |
| `BLADE_LORA_MIN_CONFIDENCE` | `0.9` | 이 미만이면 `manual_review`로 보류. |

### 런타임 동작 (대개 기본값으로 충분)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `BLADE_FAIL_MODE` | `open` | 정책/평가 불가 시 `open`=통과, `closed`=차단. **운영은 `closed`.** |
| `BLADE_ADMIN_URL` | `http://127.0.0.1:8100` | admin API 주소. |
| `BLADE_PROXY_HOST` | `127.0.0.1` | 프록시 바인드 호스트(외부 공개 시 `0.0.0.0`). 포트는 `8080`. |
| `BLADE_CACHE_TTL` / `BLADE_POLICY_POLL_SEC` | `60` / `5` | 정책 캐시 TTL·갱신 폴링(초). |

알림(선택) `BLADE_SLACK_WEBHOOK`·`BLADE_DISCORD_WEBHOOK`, 기능 플래그 등 전체 목록은 **[docs/configuration.md](docs/configuration.md)**.

---

## 2. 설치

Python **3.11** 필요(`>=3.11,<3.12`).

```bash
python3.11 -m venv .venv
.venv/Scripts/activate            # Windows(Git Bash)  ·  source .venv/bin/activate  (macOS/Linux)
pip install -e .
cp .env.example .env              # 그리고 BLADE_JWT_SECRET·BLADE_TARGET_URL·BLADE_DB_DSN 채우기
```

---

## 3. 실제 적용 — 내 API 앞에 세우기

### (1) 서비스 기동 (터미널 3개)

프록시는 `.env`의 `BLADE_JWT_SECRET`, `BLADE_TARGET_URL`(내 API), `BLADE_DB_DSN`(내 DB 읽기 전용)을 사용합니다.

```bash
# admin API (:8100) — 정책·탐지 저장
.venv/Scripts/python.exe -m uvicorn admin_api.main:app --host 127.0.0.1 --port 8100

# BLADE 프록시 (:8080) — .env 로드 후
.venv/Scripts/python.exe -m proxy.server

# 대시보드 (:3000, Node 불필요)
.venv/Scripts/python.exe scripts/blade_dashboard.py
```

### (2) 정책 생성 → 검토 → 승인

내 API의 **OpenAPI 명세**와 **DB 스키마/DDL**을 `/generate`에 올리면 엔드포인트별 **정책 초안(PENDING)** 이 생성됩니다. 대시보드(`:3000`)에서 버튼으로 승인하거나, 아래처럼 API로 승인합니다.

```bash
# 생성: 내 API 명세 + DB DDL (선택: 핸들러 소스를 주면 근거가 좋아짐)
curl -F "oas=@내API_openapi.json" -F "erd=@내DB_schema.sql" -F "controller=@핸들러소스.py" \
     http://127.0.0.1:8100/generate

# 생성된 정책(PENDING)과 그 id 확인
curl "http://127.0.0.1:8100/policies?status=PENDING"

# label·근거 확인 후 id로 승인
curl -X POST http://127.0.0.1:8100/policies/<정책id>/approve
```

**사람 승인(ACTIVE) 전에는 아무것도 집행되지 않습니다.** 판단이 애매한 엔드포인트는 `manual_review_required`로 보류됩니다.

### (3) 트래픽 전환 · 동작 확인

클라이언트가 내 API 대신 **프록시(`:8080`)** 로 요청하게 합니다. 호출자는 `BLADE_JWT_SECRET`으로 서명된(HS256) JWT를 지참해야 하며, 다음 클레임이 필요합니다.

| 클레임 | 설명 |
|---|---|
| `sub` | 호출자 식별자 — 소유자 비교 기준(`owner_match`). |
| `roles` | 역할 목록 — `role_required`. |
| `tenant_id` | 테넌트 — `tenant_match`. |
| `membership` | 멤버십 등급 — `membership_required`. |
| `exp` | 만료(Unix time). |

같은 토큰으로 **본인 리소스는 200, 남의 리소스는 403 BLOCK** 이 됩니다(소유자 조회는 `BLADE_DB_DSN`으로 수행).

```bash
TOKEN="<호출자 JWT>"   # 운영은 내 인증 시스템이 발급. 로컬 점검은 .venv/Scripts/python.exe -m proxy.mktoken user_99
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/<내 엔드포인트>/<본인 리소스>   # → 200
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/<내 엔드포인트>/<남의 리소스>   # → 403 BLOCK
```

> 소유자 조회용 **읽기 전용** DSN 예(SQLite): `BLADE_DB_DSN=sqlite:///file:내DB.db?mode=ro&uri=true`

### (4) 운영

`BLADE_FAIL_MODE=closed`(실패 시 차단)로 바꾸고, `BLADE_PROXY_HOST`·시크릿·DSN을 관리합니다. 정책을 바꾸면 `BLADE_POLICY_POLL_SEC` 주기 안에 반영됩니다.

정책 label 7종: `public`, `owner_match`, `owner_or_admin`, `role_required`, `membership_required`, `tenant_match`, `manual_review_required`(사람 검토 보류).

---

## 4. 대시보드 & Slack 알림

- **대시보드**(`:3000`): 미리 빌드된 정적 번들(`dashboard_dist/`)을 `scripts/blade_dashboard.py`가 서빙하며 `/api`만 admin(`:8100`)으로 넘깁니다. **Node 불필요.** 정책 승인/롤백, 탐지 로그(5초 갱신), 수동 검토 큐.
- **Slack**: `admin_api.alerts` 워커가 BLOCK 탐지를 전송합니다(admin 자체는 전송하지 않음).

```bash
# .env 에 BLADE_SLACK_WEBHOOK 추가 후
set -a; source .env; set +a
BLADE_ALERT_DB=blade.db BLADE_ALERT_CURSOR=alert-cursor .venv/Scripts/python.exe -m admin_api.alerts
```

---

## 5. 동작 방식

프록시는 요청마다 (1) `BLADE_JWT_SECRET`으로 JWT를 검증하고, (2) 경로를 ACTIVE 정책에 매칭하고, (3) 객체형 정책(`owner_match`·`tenant_match`·`owner_or_admin`)이면 `BLADE_DB_DSN`으로 소유자/테넌트를 조회해 호출자와 비교한 뒤, (4) 허용은 업스트림으로 통과시키고 차단은 403을 돌려주며 탐지를 admin에 기록합니다. 정책은 LLM 또는 LoRA 분류기가 **초안**을 만들고 **사람이 승인**해야 집행됩니다.

구성: `proxy/` 집행 · `admin_api/` 정책·탐지·생성 API · `pipeline/` 분류기·파서 · `common/` 공용 스키마 · `prompts/` 분류 프롬프트 · `dashboard_dist/`+`scripts/blade_dashboard.py` 대시보드.

---

## 6. 라이선스

Apache License 2.0 ([LICENSE](LICENSE)). `lora` 경로에서 쓰는 Qwen2.5 기반 어댑터도 Apache-2.0이며, 가중치는 메인 저장소의 릴리스에서 받습니다. 자세한 고지는 [NOTICE](NOTICE).
