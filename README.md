# 🔍 Axios Supply Chain Attack Scanner

A single-command scanner to check if your machine was affected by the **Axios npm supply chain compromise** (March 31, 2026).

On March 31, 2026, a threat actor compromised the official Axios npm maintainer account and published two malicious versions — `axios@1.14.1` and `axios@0.30.4` — containing a hidden dependency (`plain-crypto-js`) that deployed a cross-platform RAT (Remote Access Trojan) on macOS, Windows, and Linux.

**Safe versions:** `axios@1.14.0` | `axios@0.30.3`

## ⚡ Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/luivc1/axios-supply-chain-scanner/main/axios-scan.sh -o axios-scan.sh
chmod +x axios-scan.sh
./axios-scan.sh
```

Or clone and run:

```bash
git clone https://github.com/luivc1/axios-supply-chain-scanner.git
cd axios-supply-chain-scanner
chmod +x axios-scan.sh
./axios-scan.sh
```

## 🔎 What It Scans

| Area | What it checks |
|---|---|
| **Lockfiles** | Every `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` for malicious versions |
| **node_modules** | Installed `axios` version + presence of `plain-crypto-js` |
| **Global packages** | npm, yarn, and pnpm global installs |
| **Package caches** | npm/yarn/pnpm caches for lingering malicious packages |
| **RAT artifacts** | Persistence mechanisms (LaunchAgents, cron, systemd) and dropper signatures |
| **Network IOCs** | Active connections to known C2 domain (`sfrclak[.]com`) |

## 🖥️ Supported Platforms

- macOS
- Linux
- Windows (WSL / Git Bash)

## 📋 Output

The script prints a color-coded summary in your terminal and saves a detailed log to:

```
~/axios-scan-results-YYYYMMDD-HHMMSS.log
```

**✅ Clean result:**
```
✅ ALL CLEAR — No compromised Axios found.
```

**🚨 If compromised:**
```
🚨 X ISSUE(S) FOUND — ACTION REQUIRED
```

## 🚨 What To Do If You're Affected

1. **Downgrade immediately** to `axios@1.14.0` or `axios@0.30.3`
2. **Delete** `node_modules/plain-crypto-js` in every project
3. **Purge caches:** `npm cache clean --force`
4. **Nuke and reinstall:** delete `node_modules`, reinstall from a clean lockfile
5. **Rotate ALL secrets** — API keys, tokens, SSH keys, DB passwords, `.env` vars, CI/CD secrets
6. **Block** egress traffic to `sfrclak[.]com` at your firewall/DNS
7. **Audit CI/CD logs** from March 31, 00:21–03:30 UTC for any builds that ran `npm install`

## 📚 References

- [Microsoft — Mitigating the Axios npm supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)
- [Elastic Security Labs — Inside the Axios supply chain compromise](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)
- [Snyk — Axios npm Package Compromised](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [SANS — Axios NPM Supply Chain Compromise](https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan)
- [GitHub Issue — axios/axios#10604](https://github.com/axios/axios/issues/10604)

## 🤝 Contributing

Found something the scanner misses? PRs welcome. Open an issue or submit a pull request.

## 📄 License

MIT — use it, share it, protect your team.
