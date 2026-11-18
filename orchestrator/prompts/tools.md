# Tool notes (reference for the agent/system prompt)

These are the kinds of tools typically available in the attacker container and how they're used
against lab web targets. The exact allow-list is injected from the active profile.

- `nmap -sV <ip>`            — service/version discovery on an in-scope host
- `whatweb http://<ip>:<port>/` — fingerprint the web stack
- `curl -i http://<ip>:<port>/path` — fetch endpoints, inspect headers/responses
- `gobuster dir -u http://<ip>:<port> -w <wordlist>` — content discovery
- `ffuf -u http://<ip>:<port>/FUZZ -w <wordlist>` — fuzzing endpoints/params
- `sqlmap -u "http://<ip>:<port>/path?q=1" --batch` — automated SQLi testing
- `nikto -h http://<ip>:<port>/` — web server misconfig/vuln scan
- `hydra`                    — credential brute force against a discovered login (in-scope only)
- `cat` / `ls` / `grep`      — read files and search output once you have access

Scope reminder: every host/URL must be inside the lab CIDR. The safety layer enforces this; a
command that points anywhere else is rejected before it runs.
