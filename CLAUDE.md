# iscooked — Claude Context

## Cardinal rule: Claude never deploys iscooked

Prod deploys are **human-only**. Jack runs the publishing runbook himself.
- Canonical path: Obsidian vault note `52.02 Publishing Runbook`
- Blog content (`site/blog/*`) is gitignored — lives only locally + on Pages
- Direct Upload Pages project; no Git integration (by design — Git-connected would break the blog flow)

Enforcement:
- `.claude/settings.json` blocks `wrangler pages deploy ... --branch=master|main`
- `.claude/settings.json` blocks `git push ... origin master`
- `scripts/hooks/pre-push` blocks direct push to `master`/`main` (install: `./scripts/hooks/install.sh`)
- Global `~/.claude/settings.json` also blocks prod-branch wrangler deploys repo-wide

## Repo shape

- **CF project:** `iscooked` (Direct Upload)
- **Domains:** `iscooked.com`, `www.iscooked.com`, `iscooked.pages.dev`
- **Default branch:** `master`
- **Build:** `cooked.sh` → `site/` → wrangler deploy (Jack-only)

## What Claude can do

- Edit source (`blog-src/`, `cooked.sh`, `site/` non-blog assets, configs)
- Commit to feature branches, push feature branches, open PRs
- Preview builds locally (`cooked.sh` build-only, no deploy)

## What Claude cannot do

- Run `wrangler pages deploy` against prod branches
- Push to `master` directly
- Migrate Pages project to Git integration (would break blog publishing)
