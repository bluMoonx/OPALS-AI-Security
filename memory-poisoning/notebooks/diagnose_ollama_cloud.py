"""
diagnose_ollama_cloud.py

Calls Ollama Cloud directly, bypassing Docker/OpenClaw entirely, to check
whether a 429 is a real account-level quota issue vs. something specific
to the OpenClaw gateway setup.
"""
import requests

API_KEY = "146da28375c94fb885ba46132fbf98ad.R31FG7LDbvoRCGlGU5SE4F7o"  # do not share this file/output with the key visible

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

print("=== Checking /api/chat ===")
resp = requests.post(
    "https://ollama.com/api/chat",
    headers=headers,
    json={
        "model": "kimi-k2.5",
        "messages": [{"role": "user", "content": "Say hello in one word."}],
        "stream": False,
    },
    timeout=30,
)
print("Status:", resp.status_code)
print("Body:", resp.text[:500])

print("\n=== Checking /api/tags (list available models) ===")
resp2 = requests.get("https://ollama.com/api/tags", headers=headers, timeout=30)
print("Status:", resp2.status_code)
print("Body:", resp2.text[:500])