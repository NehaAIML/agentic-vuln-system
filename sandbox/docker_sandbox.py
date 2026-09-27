import subprocess
from pathlib import Path

def run_in_docker(repo_dir: str) -> dict:
    """Spawns an ephemeral Docker container to execute tests safely in total isolation."""
    print("[DockerSandbox] Building ephemeral container environment...")
    
    # Write a lightweight Dockerfile on the fly if not present
    dockerfile_content = """
    FROM python:3.11-slim
    WORKDIR /app
    COPY . /app
    RUN pip install --no-cache-dir pytest requests
    CMD ["pytest"]
    """
    Path("Dockerfile").write_text(dockerfile_content.strip())
    
    try:
        # Build ephemeral test image
        subprocess.run(["docker", "build", "-t", "vuln-agent-sandbox:latest", "."], check=True, capture_output=True)
        
        # Run tests inside container isolation
        print("[DockerSandbox] Executing test suite inside container sandbox...")
        result = subprocess.run(
            ["docker", "run", "--rm", "vuln-agent-sandbox:latest"],
            capture_output=True,
            text=True
        )
        
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e)
        }
