# 🔥 iscooked.com — Am I Cooked?

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Bash](https://img.shields.io/badge/bash-3.2%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)

**One-command security scanner for local AI setups.** Find out if your Ollama, LM Studio, or self-hosted LLM is leaking like a sieve.

```bash
curl -fsSL iscooked.com/iscooked.com | bash
```

## Quick Start

```bash
# Option 1: Run directly
curl -fsSL iscooked.com/iscooked.com | bash

# Option 2: Download first
wget https://iscooked.com/iscooked.com
chmod +x iscooked.com
./iscooked.com

# Option 3: With sudo for deeper checks
curl -fsSL iscooked.com/iscooked.com | sudo bash
```

## What it checks

| Check | What it looks for |
|---|---|
| **Network Exposure** | AI services listening on 0.0.0.0 instead of localhost |
| **API Authentication** | Ollama, LM Studio, Open WebUI running without auth |
| **File Permissions** | Model files and directories world-readable/writable |
| **Docker Risks** | AI containers running as root, privileged mode, host networking |
| **GPU Exposure** | NVIDIA/AMD device permissions and management endpoints |
| **Telemetry** | Active connections to known telemetry domains |
| **Firewall Status** | UFW, firewalld, iptables, nftables — is anything running? |
| **SSL/TLS** | AI services exposed over plain HTTP on non-localhost |
| **Process Audit** | AI processes and what user they're running as |
| **Sensitive Files** | .env files with API keys readable by other users |
| **History & Logs** | API keys leaked in shell history, world-readable log dirs |
| **Ollama Config** | OLLAMA_HOST, OLLAMA_ORIGINS, systemd service checks |

## Supported Tools

| Tool | Checked |
|---|---|
| Ollama | ✅ |
| LM Studio | ✅ |
| Open WebUI | ✅ |
| text-generation-webui | ✅ |
| ComfyUI | ✅ |
| vLLM | ✅ |
| LocalAI | ✅ |
| KoboldCpp | ✅ |
| Stable Diffusion WebUI | ✅ |
| Whisper | ✅ |

## Example output

```
  🔥 COOKED   Ollama (port 11434) is listening on ALL interfaces
  ✅ SAFE      LM Studio (port 1234) is bound to localhost only
  ⚠  WARMING UP  Ollama API is responding without authentication
  🔥 COOKED   No active firewall detected!
  🔥 COOKED   Shell history contains ~3 potential API key(s)

  YOUR COOKED SCORE

  73% cooked  [██████████████████████████████          ]

  FULLY COOKED

  3 critical  1 warnings  2 passed

  You are absolutely cooked. Fix the critical issues above ASAP.
```

## Scoring

| Score | Level | Meaning |
|---|---|---|
| 0–14% | **Looking Fresh** | Your setup is locked down. |
| 15–39% | **Slightly Warm** | A few things to tighten up. |
| 40–69% | **Medium Rare** | Address those warnings. |
| 70–100% | **Fully Cooked** | Fix the critical issues now. |

## Cross-platform

Works on **Linux** and **macOS** (bash 3.2+). Uses standard Unix tools (`ss`/`netstat`, `ps`, `stat`, `find`). Optional: `curl`, `docker`, `nvidia-smi` for deeper checks. Run with `sudo` for more thorough firewall and port checks.

## Privacy

Runs **entirely on your machine**. Makes no network requests, sends no telemetry, and phones home to absolutely nobody.

## Contributing

PRs welcome! Some ideas:

- [ ] Add checks for more AI tools (TabbyAPI, etc.)
- [ ] JSON output mode for CI/CD integration
- [ ] Auto-fix mode for common issues
- [x] macOS-specific checks
- [ ] WSL-specific checks

## License

MIT — do whatever you want with it.

## See Also

Running local LLMs? Find the best models for your hardware at [llmscout.fit](https://llmscout.fit).

---

Built by a cybersecurity engineer who runs local LLMs. [GitHub](https://github.com/dinosoup1/iscooked) | [iscooked.com](https://iscooked.com)
