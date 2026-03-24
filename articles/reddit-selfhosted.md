# Title: Security scanner for self-hosted AI/LLM setups — one command, no dependencies

# Subreddit: r/selfhosted

Hey r/selfhosted — I built a security scanner specifically for self-hosted AI setups (Ollama, LM Studio, Open WebUI, vLLM, ComfyUI, etc.).

Most of these tools ship with insecure defaults — Ollama binds to all interfaces, no auth on API endpoints, Docker containers running as root. If you're on a home network with other devices, this stuff matters.

**iscooked** runs 12 checks and gives you a cooked score:

```
curl -fsSL iscooked.com/iscooked.com | bash
```

What it scans:
- Network exposure (0.0.0.0 binding on AI ports)
- API authentication gaps
- File permissions (.env files, model dirs)
- Docker container security (root, privileged, host networking)
- GPU device permissions
- Firewall status (ufw, firewalld, iptables, nftables)
- Shell history API key leakage
- SSL/TLS on exposed services
- Ollama-specific config (OLLAMA_HOST, OLLAMA_ORIGINS)

No dependencies, no install, runs entirely locally. Works on Linux and macOS.

GitHub: https://github.com/dinosoup1/iscooked

Feedback welcome — what checks would you add?
