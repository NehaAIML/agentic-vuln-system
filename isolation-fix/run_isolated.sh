#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-agentic-vuln-isolated:latest}"
CONTAINER_NAME_PREFIX="agentic-vuln-run"

MEMORY_LIMIT="${MEMORY_LIMIT:-2g}"
CPU_LIMIT="${CPU_LIMIT:-2.0}"
PIDS_LIMIT="${PIDS_LIMIT:-256}"
NETWORK_MODE="bridge"
BUILD_ONLY=0
PIPELINE_ARGS=()

usage() {
  cat <<EOH
Usage: $(basename "$0") [wrapper-options] <repo_path> [pipeline-args...]

Wrapper options:
  --build-only          Only build the Docker image, then exit
  --no-network          Run with --network=none (offline / mock / dry-run only)
  --memory <limit>      Memory limit (default: 2g)
  --cpus <limit>        CPU limit (default: 2.0)
  --image <name>        Image name (default: agentic-vuln-isolated:latest)
  -h, --help            Show this help
EOH
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-only) BUILD_ONLY=1; shift ;;
    --no-network) NETWORK_MODE="none"; shift ;;
    --memory) MEMORY_LIMIT="$2"; shift 2 ;;
    --cpus) CPU_LIMIT="$2"; shift 2 ;;
    --image) IMAGE_NAME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; PIPELINE_ARGS+=("$@"); break ;;
    -*) PIPELINE_ARGS+=("$@"); break ;;
    *)  PIPELINE_ARGS+=("$@"); break ;;
  esac
done

build_image() {
  echo "==> Building image ${IMAGE_NAME}"
  docker build -t "${IMAGE_NAME}" -f "${SCRIPT_DIR}/Dockerfile" "${REPO_ROOT}"
}

if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
  echo "Image not found — building..."
  build_image
elif [[ "${FORCE_REBUILD:-0}" == "1" ]]; then
  build_image
fi

if [[ "${BUILD_ONLY}" -eq 1 ]]; then
  echo "Build complete: ${IMAGE_NAME}"
  exit 0
fi

if [[ ${#PIPELINE_ARGS[@]} -eq 0 ]]; then
  echo "Error: repo_path required"
  usage
  exit 1
fi

TARGET_REPO_HOST="${PIPELINE_ARGS[0]}"
if [[ ! -d "${TARGET_REPO_HOST}" ]]; then
  if [[ -d "${REPO_ROOT}/${TARGET_REPO_HOST}" ]]; then
    TARGET_REPO_HOST="${REPO_ROOT}/${TARGET_REPO_HOST}"
  else
    echo "Error: path does not exist: ${PIPELINE_ARGS[0]}"
    exit 1
  fi
fi
TARGET_REPO_HOST="$(cd "${TARGET_REPO_HOST}" && pwd)"
PIPELINE_ARGS=("${PIPELINE_ARGS[@]:1}")

DOCKER_RUN_ARGS=(
  --rm
  --name "${CONTAINER_NAME_PREFIX}-$$"
  --user "1000:1000"
  --cap-drop=ALL
  --security-opt=no-new-privileges:true
  --memory="${MEMORY_LIMIT}"
  --cpus="${CPU_LIMIT}"
  --pids-limit="${PIDS_LIMIT}"
  --read-only
  --tmpfs /tmp:rw,noexec,nosuid,size=512m
  --tmpfs /home/vuln:rw,noexec,nosuid,size=64m
  --network="${NETWORK_MODE}"
  -v "${REPO_ROOT}:/opt/agentic-vuln:ro"
  -v "${TARGET_REPO_HOST}:/work/target:rw"
  -w /opt/agentic-vuln
  -e "HOME=/home/vuln"
  -e "PYTHONUNBUFFERED=1"
  -e "MAX_REPAIR_ATTEMPTS=${MAX_REPAIR_ATTEMPTS:-3}"
)

# Pass through API keys if they exist in the host environment
for var in GROQ_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST; do
  if [[ -n "${!var:-}" ]]; then
    DOCKER_RUN_ARGS+=(-e "${var}=${!var}")
  fi
done

if [[ "${NETWORK_MODE}" != "none" && -n "${OLLAMA_HOST:-}" ]]; then
  DOCKER_RUN_ARGS+=(--add-host=host.docker.internal:host-gateway)
fi

echo "==> Running in isolated container"
echo "    Target (host): ${TARGET_REPO_HOST}"
echo "    Network:       ${NETWORK_MODE}"

CMD=(python3 run_pipeline.py /work/target "${PIPELINE_ARGS[@]}")

# Best-effort fix for sample_repo mock paths inside the container
for i in "${!CMD[@]}"; do
  if [[ "${CMD[$i]}" == "--mock" && $((i+1)) -lt ${#CMD[@]} ]]; then
    mock_path="${CMD[$((i+1))]}"
    if [[ "${mock_path}" == sample_repo/* ]]; then
      CMD[$((i+1))]="/opt/agentic-vuln/${mock_path}"
    fi
  fi
done

docker run "${DOCKER_RUN_ARGS[@]}" "${IMAGE_NAME}" "${CMD[@]}"

echo ""
echo "==> Done. Results are in: ${TARGET_REPO_HOST}"
