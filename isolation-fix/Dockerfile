FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.description="Isolated runner for agentic-vuln-system"

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 vuln && \
    useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash vuln

WORKDIR /opt/agentic-vuln

# Copy core directories and files (avoids copying .venv or .git)
COPY --chown=vuln:vuln agent/ sandbox/ scanners/ utils/ dashboard/ tests/ sample_repo/ benchmarks/ docs/ ./
COPY --chown=vuln:vuln run_pipeline.py simulate.py create_pr.py generate_contexts.py requirements.txt pyproject.toml ./

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pytest responses

# Install sample repo dependencies if they exist
RUN if [ -f sample_repo/requirements.txt ]; then \
        pip install --no-cache-dir -r sample_repo/requirements.txt; \
    fi

USER vuln
ENTRYPOINT ["python3"]
CMD ["run_pipeline.py", "--help"]
