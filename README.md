# jwt-sample

실무에서 참고할 수 있는 JWT 인증 샘플 프로젝트입니다.

- **Access Token**: JWT (HS256), 서버 미저장, React Zustand 메모리 보관, `Authorization: Bearer` 헤더 전송
- **Refresh Token**: HttpOnly Cookie, Redis에 해시값만 저장, TTL + Rotation 적용
- **영속 데이터**: MySQL (User)
- **Refresh Token 저장소**: Redis

## 프로젝트 구조

```
jwt-sample/
├── backend/springboot/     # Spring Boot 3.5 + Spring Security
├── frontend/react/         # Vite + React SPA
├── docker-compose.yml      # MySQL 8 + Redis 7
├── .env.example            # Docker용 환경 변수 템플릿
└── README.md
```

### Backend 패키지 구조 (MVC 레이어 기준)

```
com.jwtsample.springboot/
├── controller/          # 컨트롤러
│   ├── auth/
│   └── user/
├── model/               # 엔티티, Repository, Service
│   ├── auth/
│   └── user/
├── view/                # 요청/응답 DTO
│   ├── auth/
│   └── user/
├── config/              # Spring 설정
├── security/            # JWT, 인증 필터
└── common/              # 예외 처리, CSRF 필터
```

## 기술 스택

### Backend

| 항목 | 버전 |
|------|------|
| Java | 17 |
| Spring Boot | 3.5.16 |
| Spring Security | starter 포함 |
| JJWT | 0.12.6 |
| MySQL | 8 (Docker) |
| Redis | 7 (Docker) |

### Frontend

| 패키지 | 버전 |
|--------|------|
| react | ^19.2.7 |
| react-dom | ^19.2.7 |
| vite | ^8.1.0 |
| typescript | ~6.0.2 |
| axios | ^1.18.1 |
| zustand | ^5.0.14 |
| react-router-dom | ^7.18.0 |

## 사전 요구사항

- Docker / Docker Compose
- Java 17+
- Node.js 20+

## 실행 방법

### 1. 로컬 설정 파일 준비

**Spring Boot** — `application-local.yml` 복사 후 **자리표시자를 실제 값으로 변경**:

```bash
cp backend/springboot/src/main/resources/application-local.yml.example \
   backend/springboot/src/main/resources/application-local.yml
```

`application-local.yml`은 DB 접속 정보, JWT 시크릿 등을 직접 작성합니다. **Git에 커밋하지 않습니다.**

**Docker** — `.env` 복사 후 **자리표시자를 실제 값으로 변경**:

```bash
cp .env.example .env
```

`.env`는 MySQL/Redis 컨테이너 설정 전용입니다. **Git에 커밋하지 않습니다.**

> `.example` 파일에는 `your_mysql_password` 같은 **자리표시자만** 들어 있습니다. 실제 비밀번호·시크릿은 복사한 `.env` / `application-local.yml`에만 작성하세요.  
> `application-local.yml`의 DB 계정(`username`, `password`, DB명)은 `.env`의 `MYSQL_*` 값과 **일치**해야 합니다.

나중에 React에서 환경 변수가 필요하면 `frontend/react/.env`에 `VITE_` 접두사로 별도 관리합니다.

### 2. MySQL + Redis 실행

```bash
docker compose up -d
```

Docker Compose가 루트 `.env`를 자동으로 읽습니다. `docker-compose.yml`에는 비밀번호를 넣지 않습니다.

컨테이너 상태 확인:

```bash
docker compose ps
```

### 3. Backend 실행

```bash
cd backend/springboot
./gradlew bootRun
```

`application.yaml`에 `spring.profiles.active: local`이 기본 설정되어 있어 `application-local.yml`이 자동 로드됩니다.

서버: `http://localhost:8080`

### 4. Frontend 실행

```bash
cd frontend/react
npm install
npm run dev
```

앱: `http://localhost:5173`

Vite dev server가 `/api` 요청을 `http://localhost:8080`으로 프록시합니다.

### 5. 동작 확인

1. `http://localhost:5173/signup`에서 회원가입
2. 로그인
3. 홈 화면에서 `/api/users/me` 응답(사용자 정보) 확인
4. 새로고침 후에도 Cookie 기반 silent refresh로 로그인 상태 복구 확인
5. 로그아웃 후 보호 라우트 접근 시 로그인 페이지로 이동 확인

## API 엔드포인트

| Method | Path | 인증 | 설명 |
|--------|------|------|------|
| POST | `/api/auth/signup` | 공개 | 회원가입 |
| POST | `/api/auth/login` | 공개 | 로그인 → accessToken(JSON) + refresh Cookie |
| POST | `/api/auth/refresh` | Cookie | accessToken 재발급 + refresh Rotation |
| POST | `/api/auth/logout` | Cookie | Redis Refresh Token 삭제 + Cookie 만료 |
| GET | `/api/users/me` | Bearer JWT | 현재 사용자 정보 |

## 인증 흐름

```
[로그인]
  Client → POST /api/auth/login
  Server → BCrypt 검증 → Access JWT 발급 + Refresh Cookie 설정
           Redis에 refresh token 해시 저장 (TTL)

[API 호출]
  Client → Authorization: Bearer {accessToken}
  Server → JWT 서명/만료 검증 (서버 상태 없음)

[토큰 갱신]
  Client → POST /api/auth/refresh (Cookie 자동 전송)
  Server → Redis 해시 검증 → Rotation(새 rawToken + 새 해시) → 새 Access JWT

[로그아웃]
  Client → POST /api/auth/logout (Cookie)
  Server → Redis Refresh Token 삭제 + Cookie 만료
```

## CSRF 방어 전략

Refresh/Logout은 HttpOnly Cookie를 사용하므로 CSRF 공격 표면이 존재합니다.

Spring Security CSRF는 **Bearer JWT 기반 stateless API**에 맞춰 비활성화합니다.  
`csrf.disable()`만으로 끝내지 않고, Cookie 엔드포인트에 **3중 방어**를 적용합니다.

| 계층 | 적용 대상 | 구현 |
|------|----------|------|
| 1. SameSite Cookie | refresh Cookie | `SameSite=Strict` — cross-site 요청 시 브라우저가 Cookie 미전송 |
| 2. Origin/Referer 검증 | `POST /api/auth/refresh`, `POST /api/auth/logout` | `CookieCsrfDefenseFilter`에서 허용 Origin 화이트리스트(`app.cors.allowed-origins`)와 대조 |
| 3. 커스텀 헤더 요구 | 동일 엔드포인트 | `X-Requested-With: XMLHttpRequest` 필수 — 단순 `<form>` CSRF 차단 |

### Spring CSRF를 비활성화하는 이유

- 대부분의 API는 `Authorization: Bearer` 헤더로 인증하며, 브라우저가 자동으로 첨부하지 않습니다.
- Spring CSRF 토큰은 세션 기반 앱에 적합하고, SPA + JWT 조합에서는 별도 전략이 필요합니다.
- Cookie를 사용하는 refresh/logout만 위 3중 방어로 별도 보호합니다.

### 프론트엔드 대응

`authApi.ts`의 refresh/logout 호출 시 `X-Requested-With: XMLHttpRequest` 헤더를 항상 포함합니다.

### Refresh Cookie `Secure` 플래그

| 환경 | `app.cookie.secure` | 비고 |
|------|---------------------|------|
| 로컬 (`localhost`, `127.0.0.1`) | `true` 권장 | 최신 브라우저는 HTTP여도 Secure 쿠키 저장·전송 허용 |
| LAN IP (`http://192.168.x.x` 등) | `false` 필요할 수 있음 | Secure 쿠키가 저장되지 않아 refresh 실패 가능 |
| 운영 (HTTPS) | `true` 필수 | HTTP에서는 Secure 쿠키 미전송 |

로컬도 운영과 맞추려면 `application-local.yml`에서 `secure: true`로 두면 됩니다.

### 운영 환경 주의사항

- HTTPS 사용 필수 (`app.cookie.secure: true`)
- `JWT_SECRET`, `REFRESH_TOKEN_PEPPER`는 시크릿 관리 도구로 주입
- CORS `allowed-origins`를 실제 프론트엔드 도메인으로 제한

## Refresh Token 보안

- Redis에는 **원문이 아닌** `SHA-256(rawToken + pepper)` 해시만 저장
- **Rotation**: refresh 성공 시 새 rawToken 발급 + Redis 해시 교체 + Cookie 갱신
- **Reuse Detection**: rotation 이후 이전 토큰 재사용 시 해당 사용자의 모든 refresh token 무효화

## Redis 키 구조

```
refreshToken:{refreshTokenId}              →  {userId}:{tokenHash}   (TTL = refresh 만료)
refreshToken:user:{userId}                 →  Set<refreshTokenId>     (사용자별 Refresh Token 목록)
refreshToken:grace:{refreshTokenId}:{oldHash} →  1 (마커, TTL 30초 — 원문/해시 미저장)
```

- Grace 중복 요청 시 access token만 재발급하고 `Set-Cookie`는 생략 (첫 rotation 응답 또는 프론트 single-flight가 Cookie 갱신 담당)
- Cookie 값: `{refreshTokenId}.{rawToken}`
- `redis-cli KEYS "refreshToken:*"` 로 조회

## 로컬 설정 파일

| 파일 | Git | 용도 |
|------|-----|------|
| `.env.example` | 커밋 | Docker 환경 변수 템플릿 (자리표시자만, 비밀번호 없음) |
| `.env` | **제외** | Docker Compose 실제 값 |
| `application-local.yml.example` | 커밋 | Spring Boot 로컬 설정 템플릿 (자리표시자만, 시크릿 없음) |
| `application-local.yml` | **제외** | Spring Boot 실제 값 (DB, JWT 시크릿 등) |
| `docker-compose.yml` | 커밋 | 컨테이너 구조만 정의 (`${VAR}` 참조) |
| `frontend/react/.env` | 제외 (필요 시) | React/Vite 전용 (`VITE_` 접두사) |

### 설정 분리 원칙

```
.env                    → Docker (MySQL/Redis 컨테이너)
application-local.yml   → Spring Boot (DB 접속, JWT, CORS 등)
frontend/react/.env     → React (필요 시)
```

`docker-compose.yml`은 Git에 올라가므로 비밀번호를 직접 넣지 않고 `.env`를 참조합니다.  
`application-local.yml`의 DB 계정은 `.env`의 `MYSQL_*`와 맞춰 주세요.

## 확장 포인트

- Flyway/Liquibase 마이그레이션 (`ddl-auto: update` 대체)
- Rate limiting, 계정 잠금, 이메일 인증
- RS256 비대칭 키 (현재 HS256)
- 운영 배포 설정 (HTTPS, Secure Cookie, 시크릿 로테이션)
