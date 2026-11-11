# 설정 레퍼런스

모든 설정은 환경변수(또는 `.env`)로 줍니다. "기본값"은 코드 기본값입니다. 플래그는 `true`/`1` 등 참값일 때 켜지며, 별도 표기가 없으면 **기본 off**입니다.

> 비밀값(`*_SECRET`, `*_API_KEY`, `*_WEBHOOK`)은 커밋·로그·화면에 노출하지 마세요.

## 핵심 (proxy)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `BLADE_JWT_SECRET` | — (필수) | 호출자 JWT 검증용 HMAC 시크릿. |
| `BLADE_TARGET_URL` | `http://127.0.0.1:9000` | 보호 대상(업스트림) API. |
| `BLADE_ADMIN_URL` | `http://127.0.0.1:8100` | admin API 주소. |
| `BLADE_FAIL_MODE` | `open` | `open`=실패 시 통과, `closed`=실패 시 차단. |
| `BLADE_DB_DSN` | `sqlite:///demo.db` | 소유자/테넌트 조회용 읽기 전용 DSN. |
| `BLADE_PROXY_HOST` | `127.0.0.1` | 프록시 바인드 호스트(포트 `8080` 고정). |
| `BLADE_CACHE_TTL` | `60` | 조회 캐시 TTL(초). |
| `BLADE_POLICY_POLL_SEC` | `5` | 정책 갱신 폴링(초). |

## 분류기 (정책 생성)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `BLADE_CLASSIFIER` | `llm` | `llm` 또는 `lora`. lora 실패 시 llm으로 폴백. |
| `BLADE_LLM_PROVIDER` | — | `openai` \| `anthropic` \| `ollama` (llm 경로 필수). |
| `BLADE_LLM_MODEL` | — | 제공자 모델 이름. |
| `OPENAI_API_KEY` | — | provider=openai. |
| `ANTHROPIC_API_KEY` | — | provider=anthropic. |
| `BLADE_LLM_TIMEOUT` | (코드 기본) | LLM 요청 타임아웃(초). |
| `BLADE_PROMPT_VERSION` | (코드 기본) | llm 분류 프롬프트 버전(`prompts/`). |
| `BLADE_CONTROLLER_ENABLED` | off | 핸들러 소스 파싱(tree-sitter, `controller` 선택 의존성). |
| `BLADE_OLLAMA_URL` | `http://127.0.0.1:11434` | 로컬 Ollama. |
| `BLADE_LORA_MODEL` | `blade-qwen-lora-v4` | lora 경로 Ollama 모델(릴리스는 `blade-qwen-lora-v7`). |
| `BLADE_LORA_MIN_CONFIDENCE` | `0.9` | 미만이면 `manual_review`로 보류. |
| `BLADE_LORA_PROMPT_PATH` | (코드 기본) | lora 시스템 프롬프트 경로. |
| `BLADE_LORA_TIMEOUT` | (코드 기본) | lora 추론 타임아웃(초). |

## 알림 (admin_api.alerts 워커)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `BLADE_SLACK_WEBHOOK` | — | Slack Incoming Webhook URL. |
| `BLADE_DISCORD_WEBHOOK` | — | Discord Webhook URL. |
| `BLADE_ALERT_DB` | `/data/blade.db` | 워커가 읽는 탐지 DB(= admin이 쓰는 `blade.db`). |
| `BLADE_ALERT_CURSOR` | `/state/cursor` | 전송 커서 파일. |

## 선택 기능 플래그 (기본 off)

| 변수 | 설명 |
|---|---|
| `BLADE_OBSERVABILITY_ENABLED` | 프록시/admin 지표 집계. |
| `BLADE_MODE_ENABLED` | 정책별 `enforce`/`observe` 모드 전환. |
| `BLADE_ALERTS_ENABLED` | 대시보드 "알림 설정" 탭. |
| `BLADE_EXPLAIN_ENABLED` | 탐지 설명 생성(워커). |
| `BLADE_REANALYSIS_ENABLED` | 관측 기반 정책 재분석(워커). |
| `BLADE_RAG_ENABLED` | 근거 검색(무거운 `rag` 선택 의존성). |
| `BLADE_PHASE2_ENABLED` | Phase 2 기능군. |
| `BLADE_DETECTION_BATCH_ENABLED` | 탐지 배치 기록. |
| `BLADE_DETECTION_STREAM_ENABLED` | Redis 탐지 스트림. |
| `BLADE_LOOKUP_BATCH_ENABLED` | 소유자 조회 배치. |
| `BLADE_REDIS_ENABLED` / `BLADE_REDIS_URL` | Redis 기반 정책 배포. |
| `BLADE_REDIS_LOCAL_CACHE_ENABLED` | 프록시 로컬 캐시. |

## 고급

- **재분석 워커**: `BLADE_REANALYSIS_OBSERVE_THRESHOLD`, `BLADE_REANALYSIS_MIN_REQUESTS`, `BLADE_REANALYSIS_MIN_SUBJECTS`, `BLADE_REANALYSIS_WOULD_BLOCK_RATIO`, `BLADE_REANALYSIS_POLL_SEC`.
- **RAG**: `BLADE_CVE_ENABLED`, `BLADE_CVE_CORPUS`, `BLADE_RAG_KINDS`, `BLADE_EMBED_MODEL`, `BLADE_MODEL_CACHE`, `BLADE_CHROMA_PATH`.
- **탐지 스트림**: `BLADE_DETECTION_STREAM_NAMESPACE`, `BLADE_DETECTION_REDIS_URL`.
- **워커 경로**(`python -m admin_api.workers`): `BLADE_ADMIN_DB`, `BLADE_POLICY_DIR`, `BLADE_DETECTION_FILE`.

기본 설치는 핵심 + 분류기 값만 있으면 충분합니다. 위 고급·플래그는 필요할 때만 켜세요.
