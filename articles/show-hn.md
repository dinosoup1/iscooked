# Title: Show HN: iscooked – One-command security scanner for local AI setups

# URL: https://iscooked.com

# Comment to post immediately after:

Hey HN — I'm a cybersecurity engineer who runs Ollama and other local LLMs. I audited my own setup and found it was wide open: Ollama on 0.0.0.0, no firewall rules, API keys in shell history.

iscooked runs 12 security checks against your local AI setup and gives you a "cooked score" from 0-100%. One command, no dependencies, runs entirely locally:

    curl -fsSL iscooked.com/iscooked.com | bash

Checks network exposure, API auth, file permissions, Docker risks, firewall status, shell history leakage, Ollama config, and more. Works on Linux and macOS.

Source: https://github.com/dinosoup1/iscooked

Would love to hear what other checks people want — PRs welcome.
