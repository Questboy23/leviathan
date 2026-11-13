# Ideas Excluded to Keep Leviathan Simple

Each line: idea | reason excluded | simpler feature covering most of it

- Self-hosted VPN server | Costs monthly, ties traffic to one rented IP, adds no privacy over a no-log provider | `leviathan vpn` drives existing free/low-cost clients (WARP, Mullvad, Tailscale)
- Disposable VM for untrusted apps | Heavy, complex, macOS has no lightweight VM built-in | `leviathan sandbox` uses sandbox-exec (built-in, per-app container, no VM)
- Daily agent capability budgets (files written, processes spawned, MB sent) | Adds persistent daemon/state, complex accounting | Agent level 3 sandbox restricts writes to project+/tmp and network to allowlist
- Second-signer AI for dangerous commands | Adds another AI dependency, complex approval flow | `leviathan agents pause|resume` kill switch + canary tripwire auto-pause
- Bundling Palantir/alignment-monitor | External dependency, scope creep | `leviathan agents export --jsonl` outputs standard format for external tools
- Scam-site ML score | Requires model, training data, maintenance | Blocklists (hagezi, openphish, MetaMask eth-phishing-detect) are deterministic and updated hourly
- Elastic/Splunk rules export | Enterprise-only, not for personal use | Ledger is hash-chained JSONL, queryable with jq
- Real-time network proxy / MITM inspection | Requires root, breaks cert pinning, heavy | `lsof -i` sampling at level 5 + VPN DNS leak check
- Browser extension for clipboard guard | Cross-browser complexity, extension store review | Menu bar app polls NSPasteboard (works everywhere, no extension)
- Full filesystem integrity monitoring (Tripwire style) | High CPU, false positives on updates | `leviathan snapshot`/`diff` on demand + launchd WatchPaths on persist folders
- Keystroke injection detection | Requires accessibility permission, noisy | Fake password box guard kills osascript with hidden answer
- Hardware wallet USB guard | Niche, device-specific | Wallet app signature check covers Ledger Live, Trezor Suite, etc.
- Automatic malware submission to VT/HA | Privacy leak, API keys needed | YARA + Apple XProtect rules + blocklists are local and private
- Per-app network firewall (Little Snitch style) | Kernel extension, heavy, paid | `leviathan sandbox --net` deny by default, VPN DNS leak check
- Encrypted backup of quarantine | Key management complexity | Quarantine is moved, not deleted; user can back up ~/.leviathan/quarantine
- Secure boot / SIP monitoring | Read-only on Apple Silicon, SIP status in sweep | `leviathan sweep` checks spctl, FileVault, firewall
- Process injection detection (Ptrace, DYLD) | Requires DTrace/entropy, high false positive | Sandbox deny default + canary files catch data access
- Supply chain verification (Sigstore, SLSA) | Complex, needs provenance metadata | `leviathan pkg` inspects installer scripts + `snapshot`/`diff` tracks changes
- AI-generated code detection | Unreliable, arms race | Config audit flags bypassPermissions; canary tripwire catches file reads
- Biometric auth for undo | Requires Touch ID API, not in stdlib | Ledger is user-owned, undo requires local access
- Multi-user / shared Mac support | Complex permissions, launchd per-user | Designed for single-user Mac; root tool handles system dirs
- Windows / Linux port | Platform-specific APIs (launchd, codesign, sandbox-exec) | macOS-only by design