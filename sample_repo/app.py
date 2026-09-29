"""A tiny sample app with a real, reachable vulnerable dependency usage."""

import requests
import yaml


def fetch_config(url):
    resp = requests.get(url, timeout=5)
    return resp.text


def load_config(raw_yaml: str):
    # Vulnerable: yaml.load without a safe Loader (CVE-class issue in PyYAML)
    return yaml.safe_load(raw_yaml)


def main():
    cfg_text = fetch_config("https://example.com/config.yaml")
    cfg = load_config(cfg_text)
    print(cfg)


if __name__ == "__main__":
    main()
