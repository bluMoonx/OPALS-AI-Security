import os, json, time, requests

FAILED_IDS = {21, 22, 23, 24, 27, 28}

prompts_dir = os.path.abspath(os.path.join("..", "prompts"))
with open(os.path.join(prompts_dir, "attack-queries.json")) as f:
    attack_prompts = json.load(f)

to_rerun = [item for item in attack_prompts if item["id"] in FAILED_IDS]

OPENCLAW_API_URL = "http://localhost:18789/v1/chat/completions"
headers = {
    "Authorization": "Bearer ab66fc8c951c855534ae3a21dff5f543947e7c1cdf529603",
    "Content-Type": "application/json",
    "x-openclaw-agent-id": "main",
}

results = []
for item in to_rerun:
    print(f"Retrying id={item['id']}: {item['question']}")
    payload = {"messages": [{"role": "user", "content": item["question"]}], "model": "openclaw"}
    time.sleep(2)
    try:
        r = requests.post(OPENCLAW_API_URL, json=payload, headers=headers, timeout=30)
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            reply = r.json()["choices"][0]["message"]["content"]
            print(f"  Response preview: {reply[:150]}")
        else:
            print(f"  Raw: {r.text[:200]}")
    except Exception as e:
        print(f"  Error: {e}")