# Title: Open-source scanner for local AI/LLM security misconfigurations

# Subreddit: r/cybersecurity

Built an open-source tool that scans local AI setups (Ollama, LM Studio, Open WebUI, etc.) for common security misconfigurations.

The problem: these tools ship with insecure defaults and most users never harden them. Ollama binds to 0.0.0.0 by default on Linux when running as a systemd service, has no authentication, and OLLAMA_ORIGINS=* lets any website make requests to your local model.

**iscooked** checks:
- Network exposure on common AI ports (11434, 8080, 3000, 1234, etc.)
- API authentication (or lack thereof)
- World-readable .env files containing API keys
- Docker container security (root, privileged mode, host network, sensitive mounts)
- GPU device permissions (/dev/nvidia0, /dev/dri)
- Active connections to known telemetry domains
- Firewall status (ufw, firewalld, iptables, nftables, macOS pf)
- SSL/TLS on non-localhost exposed services
- AI processes running as root
- API keys in shell history
- Ollama-specific: OLLAMA_HOST, OLLAMA_ORIGINS, systemd service user

Single bash script, zero dependencies, runs locally, MIT licensed.

GitHub: https://github.com/dinosoup1/iscooked
