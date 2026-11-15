"""Minimal xAI chat completions client (stdlib only)."""
import json
import os
import urllib.request

API = "https://api.x.ai/v1/chat/completions"


def chat(messages, model, max_tokens, timeout=60):
    body = json.dumps({"model": model, "messages": messages, "max_tokens": max_tokens,
                       "temperature": 0.2}).encode()
    req = urllib.request.Request(API, data=body, headers={
        "Authorization": "Bearer " + os.environ["XAI_API_KEY"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.load(r)
    return d["choices"][0]["message"]["content"], d.get("usage", {})
