---
title: I Built a One-Command Security Scanner for Local AI Setups
published: false
description: Most Ollama and LM Studio setups are wide open. Here's a free tool to find out if yours is cooked.
tags: security, ollama, ai, opensource
cover_image: https://iscooked.com/og-image.png
canonical_url: https://iscooked.com
---

## The Problem Nobody Talks About

Everyone's running local LLMs now. Ollama has millions of downloads. LM Studio is on every developer's MacBook. Self-hosted AI is everywhere.

But here's the thing — **almost nobody secures these setups.**

I'm a cybersecurity engineer by day, and I run local LLMs at home. One afternoon I decided to audit my own setup. What I found was... not great:

- Ollama was listening on `0.0.0.0:11434` — **accessible to my entire network**
- No API authentication on any endpoint
- `.env` files with API keys were world-readable
- Shell history had API keys in plaintext
- No firewall rules for AI service ports

I was cooked. 🔥

## So I Built a Scanner

**[iscooked](https://iscooked.com)** is a one-command security scanner for local AI setups. No install, no dependencies, no sign-up:

```bash
curl -fsSL iscooked.com/iscooked.com | bash
```

It runs 12 security checks entirely on your machine and gives you a "cooked score" from 0-100%:

| Score | Rating | Meaning |
|-------|--------|---------|
| 0-14% | Looking Fresh 😎 | Your setup is locked down |
| 15-39% | Slightly Warm 🌡️ | A few things to tighten up |
| 40-69% | Medium Rare 🥩 | Time to address those warnings |
| 70-100% | Fully Cooked 🔥 | Fix the critical issues NOW |

## What It Checks

Here's the full scan breakdown:

**Network Exposure** — Is Ollama/LM Studio listening on 0.0.0.0 instead of localhost? This is the #1 risk. If you're on a shared network (coffee shop, office, dorm), anyone can talk to your model.

**API Authentication** — Ollama doesn't have auth by default. Neither does LM Studio's local server. Open WebUI might be sitting wide open on port 3000.

**File Permissions** — Model directories and `.env` files with API keys that are world-readable. On a multi-user system, this is a real problem.

**Docker Risks** — AI containers running as root? Privileged mode? Host networking? These are common in quick-start Docker Compose files.

**GPU Exposure** — NVIDIA management endpoints and `/dev/nvidia0` permissions.

**Firewall Status** — Is UFW/firewalld/iptables actually running? You'd be surprised how many developers have no firewall at all.

**Shell History** — API keys (`sk-...`, `OPENAI_API_KEY`, etc.) leaked in `.bash_history` or `.zsh_history`.

**Ollama Config** — `OLLAMA_HOST`, `OLLAMA_ORIGINS=*` (lets any website access your Ollama), systemd service running as root.

## Example Output

```
  Am I Cooked? — Local AI Security Scanner v1.0.0

  [01] Network Exposure
  ────────────────────────────────────────────
  🔥 COOKED   Ollama (port 11434) is listening on ALL interfaces
  ✅ SAFE      LM Studio (port 1234) is bound to localhost only

  [02] API Authentication
  ────────────────────────────────────────────
  ⚠  WARMING UP  Ollama API is responding without authentication

  [07] Firewall Status
  ────────────────────────────────────────────
  🔥 COOKED   No active firewall detected!

  [11] History & Logs Leakage
  ────────────────────────────────────────────
  🔥 COOKED   Shell history contains ~3 potential API key(s)

  ──────────────────────────────────────────────────

  YOUR COOKED SCORE

  73% cooked  [██████████████████████████████          ]

  FULLY COOKED

  3 critical  1 warnings  2 passed

  You are absolutely cooked. Fix the critical issues above ASAP.
```

## Cross-Platform

Works on **Linux** and **macOS** (bash 3.2+). The script detects your OS and uses the right system calls — `ss` vs `netstat`, Linux `stat` vs macOS `stat`, `socketfilterfw` for macOS Application Firewall, etc.

## Privacy-First

iscooked runs **entirely on your machine**. It makes zero network requests, sends no telemetry, and phones home to absolutely nobody. The only network activity is checking whether your local AI services respond on localhost.

You can read every line of the source: [github.com/dinosoup1/iscooked](https://github.com/dinosoup1/iscooked)

## Try It

```bash
curl -fsSL iscooked.com/iscooked.com | bash
```

Run it with `sudo` for more thorough firewall and port checks.

**Are you cooked?** Drop your score in the comments 👇

---

*Also: if you're looking for which LLMs your hardware can actually run, check out [llmscout.fit](https://llmscout.fit) — 7,700+ models matched to your exact specs.*
