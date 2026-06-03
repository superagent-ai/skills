# Environment Setup

Prepare a machine for authorized engagements. The agent proposes these steps; the user runs installs locally. No bundled automation ships with this skill.

## Tool installation (macOS example)

Use Homebrew for core tooling:

```bash
brew install nmap whois jq curl httpx nuclei dnsx ffuf amass subfinder naabu
brew install go
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau@latest
go install github.com/tomnomnom/waybackurls@latest
```

Optional Python tools (virtualenv recommended):

```bash
python3 -m venv ~/pentest-venv
source ~/pentest-venv/bin/activate
pip install wafw00f theHarvester dnsrecon
```

Optional manual installs:

- Burp Suite Community
- OWASP ZAP
- SecLists: `git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists`

## Default project layout

Create once per engagement:

```bash
export PROJECT_DIR=~/Projects/pentest-engagement
mkdir -p "$PROJECT_DIR"/{evidence/{passive,active,webapp,infra,triage,findings/{confirmed,leads}},logs,reports,targets}
```

Target list files the agent maintains:

- `targets/domains.txt`
- `targets/in_scope_domains.txt`
- `targets/web_targets.txt`
- `targets/ips.txt`
- `targets/needs-scope-confirmation.txt`

## Example commands (agent-provided, user-executed)

Passive subdomain collection:

```bash
subfinder -d example.com -silent -o "$PROJECT_DIR/evidence/passive/subfinder_example.com.txt"
```

HTTP probe:

```bash
httpx -l "$PROJECT_DIR/targets/web_targets.txt" -status-code -title -tech-detect -o "$PROJECT_DIR/evidence/active/httpx.txt"
```

Top-port scan (authorized targets only):

```bash
nmap -iL "$PROJECT_DIR/targets/ips.txt" -T4 --top-ports 1000 -sV -oA "$PROJECT_DIR/evidence/active/nmap_top1000"
```

See `references/tools.md` for the full tool map.
