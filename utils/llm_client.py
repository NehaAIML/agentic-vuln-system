import requests
import os

def query_ollama(prompt, system_prompt="You are an expert security engineer. Respond ONLY with valid code in markdown blocks."):
    url = "http://localhost:11434/api/generate"
    model_name = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    
    full_prompt = f"{system_prompt}\n\nTask: {prompt}"
    
    payload = {
        "model": model_name,
        "prompt": full_prompt,
        "stream": False,
        "options": {"temperature": 0.2}
    }
    
    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except Exception as e:
        print(f"[ERROR] Ollama request failed: {e}")
        return None
