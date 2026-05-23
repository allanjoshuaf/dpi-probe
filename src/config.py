import json
import os

DEFAULT_CONFIG = {
    "targets": [
        {"ip": "1.1.1.1", "name": "Cloudflare DNS"},
        {"ip": "8.8.8.8", "name": "Google DNS"},
        {"ip": "9.9.9.9", "name": "Quad9 DNS"}
    ],
    "domains": {
        "blocked": ["instagram.com", "facebook.com", "twitter.com", "x.com", "youtube.com"],
        "clean": ["google.com", "github.com", "cloudflare.com", "yandex.ru", "rutube.ru"]
    }
}

def load(path: str = "targets.json") -> dict:
    if not os.path.exists(path):
        print(f"[*] No config file found at {path} - using defaults")
        return DEFAULT_CONFIG

    try:
        with open(path, "r") as f:
            config = json.load(f)
        print(f"[*] Config loaded from {path}")
        return config
    except Exception as e:
        print(f"[!] Failed to load config: {e} - using defaults")
        return DEFAULT_CONFIG