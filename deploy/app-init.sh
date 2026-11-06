#!/usr/bin/env bash
# Interactively create .env for a fresh clone of this repo.
# Run via `make app-init`.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
	CYAN=$(tput setaf 6) GREEN=$(tput setaf 2) YELLOW=$(tput setaf 3) RED=$(tput setaf 1) BOLD=$(tput bold) RESET=$(tput sgr0)
else
	CYAN="" GREEN="" YELLOW="" RED="" BOLD="" RESET=""
fi

if [ -f .env ]; then
	echo "${RED}Error: .env already exists. Remove or rename it first if you really want to re-run this.${RESET}" >&2
	exit 1
fi

if [ ! -f .env.example ]; then
	echo "${RED}Error: .env.example not found next to this script's repo root.${RESET}" >&2
	exit 1
fi

echo "${CYAN}== Jungo app setup ==${RESET}"
echo "Press Enter to accept the default shown in [brackets]."
echo ""

prompt() {
	local question="$1" default="$2" answer
	read -r -p "$question [$default]: " answer
	echo "${answer:-$default}"
}

prompt_secret() {
	local question="$1" default="$2" answer
	read -rs -p "$question [$default]: " answer
	echo "" >&2
	echo "${answer:-$default}"
}

port_in_use() {
	local port="$1"
	if command -v lsof >/dev/null 2>&1; then
		lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
		return 1
	elif command -v ss >/dev/null 2>&1; then
		ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[.:]${port}\$" && return 0
		return 1
	elif command -v nc >/dev/null 2>&1; then
		nc -z -w1 127.0.0.1 "$port" >/dev/null 2>&1 && return 0
		return 1
	else
		# Last resort: bash's /dev/tcp. Not compiled into Debian/Ubuntu's bash,
		# so this branch silently never matches there — the lsof/ss checks above
		# already cover that case.
		(exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3<&-; exec 3>&-; return 0; }
		return 1
	fi
}

prompt_port() {
	local question="$1" default="$2" value confirm
	while true; do
		value=$(prompt "$question" "$default")
		if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
			echo "${RED}  -> Invalid port, must be a number between 1-65535.${RESET}" >&2
			continue
		fi
		if port_in_use "$value"; then
			read -r -p "${YELLOW}  -> Port $value looks already in use. Use it anyway? [y/N]: ${RESET}" confirm
			case "$confirm" in
				[yY]*) ;;
				*) continue ;;
			esac
		fi
		echo "$value"
		return
	done
}

prompt_app_name() {
	local question="$1" default="$2" raw normalized
	while true; do
		raw=$(prompt "$question" "$default")
		normalized=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]+/-/g; s/^[-_]+//; s/[-_]+$//')
		if [ -z "$normalized" ]; then
			echo "${RED}  -> Invalid name, try again.${RESET}" >&2
			continue
		fi
		if [ "$normalized" != "$raw" ]; then
			echo "${YELLOW}  -> Normalized to: $normalized${RESET}" >&2
		fi
		echo "$normalized"
		return
	done
}

gen_secret() {
	local secret
	if secret=$(openssl rand -hex 24 2>/dev/null) && [ -n "$secret" ]; then
		echo "$secret"
		return
	fi
	if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
		if secret=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n') && [ -n "$secret" ]; then
			echo "$secret"
			return
		fi
	fi
	# Pure-bash fallback, no external tools required (e.g. minimal Git Bash on Windows).
	local i
	secret=""
	for ((i = 0; i < 48; i++)); do
		secret+=$(printf '%x' $((RANDOM % 16)))
	done
	echo "$secret"
}

gen_key() {
	local key
	if key=$(openssl rand -base64 32 2>/dev/null) && [ -n "$key" ]; then
		echo "$key"
		return
	fi
	if [ -r /dev/urandom ] && command -v base64 >/dev/null 2>&1; then
		if key=$(head -c 32 /dev/urandom | base64 | tr -d '\n') && [ -n "$key" ]; then
			echo "$key"
			return
		fi
	fi
	# Pure-bash fallback: 43 base64url characters decode to 32 bytes.
	local alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" i
	key=""
	for ((i = 0; i < 43; i++)); do
		key+=${alphabet:$((RANDOM % 64)):1}
	done
	echo "$key"
}

APP_NAME=$(prompt_app_name "App name (used for docker container/network names)" "jungo")
DB_NAME=$(prompt "Database name" "jungo")
DB_USER=$(prompt "Database user" "postgres")
DB_PASSWORD=$(prompt_secret "Database password" "postgres")
API_SERVER_PORT=$(prompt_port "App port (host)" "8080")
while true; do
	DB_PORT=$(prompt_port "Database port (host)" "5432")
	if [ "$DB_PORT" = "$API_SERVER_PORT" ]; then
		echo "${RED}  -> Must differ from the app port ($API_SERVER_PORT).${RESET}" >&2
		continue
	fi
	break
done

while true; do
	CI_PROVIDER=$(prompt "Release CI (github/gitlab/none)" "github")
	case "$CI_PROVIDER" in
		github | gitlab | none) break ;;
		*) echo "${RED}  -> Must be github, gitlab or none.${RESET}" >&2 ;;
	esac
done

AUTH_TOKEN_HMAC_SECRET=$(gen_key)
AUTH_TOKEN_ENCRYPTION_KEY=$(gen_key)
AUTH_INTERNAL_SECRET=$(gen_secret)
TRACER_DEBUG_VALUE=$(printf '%04d' $((RANDOM % 10000)))

cleanup_on_failure() {
	rm -f .env .env.bak
}
trap cleanup_on_failure ERR INT TERM

cp .env.example .env

set_env() {
	local key="$1" value="$2" escaped
	if ! grep -q "^${key}=" .env; then
		echo "${RED}Error: ${key} not found in .env.example — script and template are out of sync.${RESET}" >&2
		exit 1
	fi
	escaped=$(printf '%s' "$value" | sed -e 's/[\/&]/\\&/g')
	sed -i.bak "s/^${key}=.*/${key}=${escaped}/" .env
}

set_env "APP_NAME" "$APP_NAME"
set_env "DB_NAME" "$DB_NAME"
set_env "DB_USER" "$DB_USER"
set_env "DB_PASSWORD" "$DB_PASSWORD"
set_env "API_SERVER_PORT" "$API_SERVER_PORT"
set_env "DB_PORT" "$DB_PORT"
set_env "AUTH_TOKEN_HMAC_SECRET" "$AUTH_TOKEN_HMAC_SECRET"
set_env "AUTH_TOKEN_ENCRYPTION_KEY" "$AUTH_TOKEN_ENCRYPTION_KEY"
set_env "AUTH_INTERNAL_SECRET" "$AUTH_INTERNAL_SECRET"
set_env "TRACER_DEBUG_VALUE" "$TRACER_DEBUG_VALUE"
rm -f .env.bak
trap - ERR INT TERM

# Release pipeline: GitHub reads .github/workflows/, GitLab reads .gitlab-ci.yml.
# In the heredocs, \$ keeps CI variables literal; only APP_NAME / GO_VERSION expand here.
RELEASE_WORKFLOW=.github/workflows/release.yml
if [ "$CI_PROVIDER" = github ] && [ ! -f "$RELEASE_WORKFLOW" ]; then
	mkdir -p .github/workflows
	cat >"$RELEASE_WORKFLOW" <<EOF
name: release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - run: go test ./...

      - name: Build
        env:
          CGO_ENABLED: "0"
          GOOS: linux
          GOARCH: arm64
        run: |
          go build -ldflags="-s -w" -o dist/api ./cmd/api
          go build -ldflags="-s -w" -o dist/console ./cmd/console
          mkdir -p dist/internal/database/primary dist/storage/uploads dist/storage/logs
          cp -r internal/database/primary/migrations internal/database/primary/functions dist/internal/database/primary/
          cp .env.example dist/
          tar -czf ${APP_NAME}-\${GITHUB_REF_NAME}-linux-arm64.tar.gz -C dist .
          # the deploy tool fetches these exact asset names
          cp dist/api api-linux-arm64
          cp dist/console console-linux-arm64

      - run: gh release create "\$GITHUB_REF_NAME" ${APP_NAME}-*.tar.gz api-linux-arm64 console-linux-arm64 --generate-notes
        env:
          GH_TOKEN: \${{ github.token }}
EOF
	echo "${GREEN}Created $RELEASE_WORKFLOW (push a v* tag to build a release)${RESET}"
fi

if [ "$CI_PROVIDER" = gitlab ] && [ ! -f .gitlab-ci.yml ]; then
	GO_VERSION=$(awk '/^go /{print $2}' go.mod)
	cat >.gitlab-ci.yml <<EOF
# Push a v* tag to build and publish a release.
stages: [build, release]

variables:
  PACKAGE_URL: "\${CI_API_V4_URL}/projects/\${CI_PROJECT_ID}/packages/generic/${APP_NAME}/\${CI_COMMIT_TAG}"

build:
  stage: build
  image: golang:${GO_VERSION}
  rules:
    - if: \$CI_COMMIT_TAG =~ /^v/
  variables:
    CGO_ENABLED: "0"
    GOOS: linux
    GOARCH: arm64
  script:
    - CGO_ENABLED=1 GOOS= GOARCH= go test ./...
    - go build -ldflags="-s -w" -o dist/api ./cmd/api
    - go build -ldflags="-s -w" -o dist/console ./cmd/console
    - mkdir -p dist/internal/database/primary dist/storage/uploads dist/storage/logs
    - cp -r internal/database/primary/migrations internal/database/primary/functions dist/internal/database/primary/
    - cp .env.example dist/
    - tar -czf ${APP_NAME}-\${CI_COMMIT_TAG}-linux-arm64.tar.gz -C dist .
    # the deploy tool fetches these exact asset names
    - cp dist/api api-linux-arm64
    - cp dist/console console-linux-arm64
    # GitLab releases only hold links, so the files go to the project's generic package registry
    - |
      for f in ${APP_NAME}-\${CI_COMMIT_TAG}-linux-arm64.tar.gz api-linux-arm64 console-linux-arm64; do
        curl --fail-with-body -H "JOB-TOKEN: \${CI_JOB_TOKEN}" --upload-file "\$f" "\${PACKAGE_URL}/\$f"
      done

release:
  stage: release
  image: registry.gitlab.com/gitlab-org/cli:latest
  rules:
    - if: \$CI_COMMIT_TAG =~ /^v/
  script:
    - echo "Releasing \$CI_COMMIT_TAG"
  release:
    tag_name: \$CI_COMMIT_TAG
    description: "Release \$CI_COMMIT_TAG"
    assets:
      links:
        - name: ${APP_NAME}-\${CI_COMMIT_TAG}-linux-arm64.tar.gz
          url: "\${PACKAGE_URL}/${APP_NAME}-\${CI_COMMIT_TAG}-linux-arm64.tar.gz"
        - name: api-linux-arm64
          url: "\${PACKAGE_URL}/api-linux-arm64"
        - name: console-linux-arm64
          url: "\${PACKAGE_URL}/console-linux-arm64"
EOF
	echo "${GREEN}Created .gitlab-ci.yml (push a v* tag to build a release)${RESET}"
fi

echo ""
echo "${CYAN}== .env created ==${RESET}"
echo "  APP_NAME=$APP_NAME"
echo "  DB_NAME=$DB_NAME"
echo "  DB_USER=$DB_USER"
echo "  API_SERVER_PORT=$API_SERVER_PORT"
echo "  DB_PORT=$DB_PORT"
echo "  AUTH_TOKEN_* / AUTH_INTERNAL_SECRET generated (see .env)"
echo "  TRACER_DEBUG_VALUE=$TRACER_DEBUG_VALUE"
check_tool() {
	local name="$1" install_cmd="$2"
	if command -v "$name" >/dev/null 2>&1; then
		echo "${GREEN}  [OK]      $name${RESET}"
	else
		echo "${YELLOW}  [MISSING] $name${RESET} — install with: $install_cmd"
	fi
}

echo "${CYAN}== CLI tools (needed for migrate-* / sqlc make targets) ==${RESET}"
check_tool "migrate" "go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
check_tool "psql" "brew install libpq && brew link --force libpq (Windows: scoop install postgresql)"
check_tool "sqlc" "go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest"

echo ""
echo "${BOLD}Next:${RESET}"
echo "  make app-dev-bg   # builds and starts App + PostgreSQL, detached"
echo "  make migrate-up   # applies migrations + seeds demo accounts (admin@jungo.com / Password@123)"
