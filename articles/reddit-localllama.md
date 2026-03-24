# Title: I built a one-command security scanner for Ollama/LM Studio setups — find out if you're "cooked"

# Subreddit: r/LocalLLaMA

I'm a cybersecurity engineer who runs local LLMs, and I got curious about how secure my own setup was. Turns out... not great. Ollama was bound to 0.0.0.0, no firewall rules, API keys in my shell history.

So I built **iscooked** — a one-liner that scans your local AI setup and tells you how "cooked" you are:

```
curl -fsSL iscooked.com/iscooked.com | bash
```

It checks 12 things: network exposure, API auth, file permissions, Docker risks, GPU access, firewall status, shell history leakage, Ollama config, and more. Runs entirely locally, sends nothing anywhere.

You get a cooked score from 0-100%:
- 0-14% = Looking Fresh
- 15-39% = Slightly Warm  
- 40-69% = Medium Rare
- 70-100% = Fully Cooked

Works on Linux and macOS. MIT licensed.

GitHub: https://github.com/dinosoup1/iscooked
Website: https://iscooked.com

Would love feedback — what other checks should it include? PRs welcome.
