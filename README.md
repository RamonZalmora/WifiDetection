# WPA2 Recovery Lab Pro

A local Windows 11 dashboard for read-only WiFi discovery and bounded, authorized offline WPA2-Personal experiments. Python 3.12, FastAPI, Native WiFi API, SQLite, and locally bundled HTML/CSS/JavaScript. No Node.js, cloud service, telemetry, packet capture, deauthentication, or network connection attempts.

**Delivery status:** source and Windows packaging scripts are provided. Linux backend and browser validation can be run here. A Windows executable has **not** been built or hardware-tested in this Linux environment. Do not distribute this as Windows-validated software until the acceptance checks below pass on Windows 11 x64. No scanner results or recovered passwords are fabricated.

## End users: Windows standalone package

After a developer builds the Windows release, extract the whole `WPA2-Recovery-Lab-Pro` directory and double-click `START.bat`. Python and developer tools are not needed on the end-user computer. The launcher opens the default browser only after the authenticated backend is ready at `http://127.0.0.1:8765`. Keep the console window open. Use **Shut down** in the dashboard or Ctrl+C in the console to exit. Closing a browser tab alone does not stop the server.

The launch URL includes a per-session token in its fragment; JavaScript moves it to browser session storage and removes it from the address bar. A bare URL in another tab has no access to the private API; run START again to open an authenticated tab. A second launch reuses a verified existing instance. Port conflicts produce a visible error rather than binding to another interface or port.

Ordinary operation needs no administrator privileges. Allow Windows Location services and desktop-app location access when Windows requires these for WiFi information. Enable the radio, install the adapter vendor's driver, and ensure WLAN AutoConfig is running. Windows can refuse scanning or return cached observations; the dashboard reports errors and freshness limits. Wait a few seconds and scan again. Manufacturer/driver fields remain unknown when Windows does not expose them.

## Developer setup

Use the existing checkout. Each cloud task already has an isolated environment; do not create another Git worktree unless explicitly requested.

Linux/macOS (offline laboratory and UI only):

```sh
cd /workspace/WifiDetection
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt -c requirements.lock
.venv/bin/python -m pytest -q
.venv/bin/python -m wpa2lab
```

Windows 11 x64 development:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt -c requirements.lock
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m wpa2lab
```

Do not expose the backend through a public proxy or change its bind address. `--no-browser` runs without opening a browser. `--data-dir PATH` overrides the per-user storage root for isolated tests. A browser in a remote cloud environment cannot access that environment's loopback server directly; local HTTP and headless browser checks are suitable there.

## Windows packaging

On a **Windows 11 x64 build machine with Python 3.12 x64**, run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-windows.ps1
```

The script creates a virtual environment, installs constrained dependencies, runs automated tests, and packages a console-mode one-file executable with PyInstaller. It fails on Linux: PyInstaller does not cross-compile Windows executables. The execution-policy override applies only to this build process; it does not change machine policy.

Output:

```text
dist/WPA2-Recovery-Lab-Pro/
  START.bat
  WPA2RecoveryLab.exe
  README.txt
  data/
  reports/
```

The executable contains the Python runtime, backend, crypto dependencies, and frontend assets. No CDN or runtime download is used. The script prints a SHA-256 hash. Code signing is not provided; an unsigned build can trigger SmartScreen or antivirus review. Verify and sign your own release before distribution as appropriate.

Runtime state uses `%LOCALAPPDATA%\WPA2RecoveryLabPro\data\history.sqlite3`, rather than writing beside an executable in a potentially read-only folder. Browser exports go to the user's selected download location. The packaged `data/` and `reports/` directories are empty organizational folders. On Linux the default is `~/.local/share/WPA2RecoveryLabPro`. The instance token file lives in the per-user storage root and is removed on clean shutdown. Do not put this directory in a shared writable location.

## Real cryptographic laboratory

1. Open **WPA2 Recovery Lab**, name a project, and confirm authorization.
2. Supply the experimental SSID (1–32 UTF-8 bytes) and a known setup passphrase (8–63 printable ASCII characters).
3. Generate synthetic EAPOL message-2 material, or import the supported authorized JSON format below.
4. Open **Password Verification**. Supply manual candidates or a UTF-8 text file, one candidate per line. A trailing newline is accepted; blank candidate lines and invalid passphrases are rejected.
5. Set the bound (1–10,000; default 1,000), start, and watch actual attempts, elapsed time, measured rate, and estimated remaining work. Only one CPU experiment runs at a time. Candidate lists larger than the bound are explicitly truncated. Cancellation is checked between derivations and before accepting a match.
6. A candidate must match the EAPOL MIC twice, using separate standard-library and `cryptography` derivation/HMAC implementations, before **VERIFIED MATCH** and the actual candidate are shown. Other terminal states are **NO MATCH FOUND**, **CANCELLED**, or **ERROR**. Validation and unsupported-import states appear before testing.

The actual algorithm is PBKDF2-HMAC-SHA1(passphrase, SSID, 4096 iterations, 32-byte PMK), the WPA pairwise key expansion PRF-512 with lexicographically ordered MACs/nonces, and a truncated 16-byte HMAC-SHA1 EAPOL MIC using the first 16 PTK bytes (KCK). This supports WPA2-CCMP descriptor version 2 only. It does not support WPA3/SAE, enterprise authentication, TKIP descriptor version 1, descriptor version 3/AES-CMAC, or raw 64-hex-digit PSKs.

Generated exchanges are **synthetic laboratory authentication material**, not exchanges captured from a router. Generation cannot help recover an unknown router password: it requires a known setup password. For an unknown password, independent authorized authentication data is a prerequisite. Nearby-network discovery does not supply it. A successful offline match authenticates the supplied verifier, not a live connection, router ownership, or capture provenance. No successful router connection is claimed.

### Import format: `wpa2lab-eapol-v1`

Only JSON with the exact following fields is accepted. Export a generated project's proof for a complete working example. To represent a genuine authorized laboratory exchange, prepare the JSON from the lab's recorded message 2 and matching message-1 ANonce; this application does not collect or convert captures.

| Field | Meaning |
| --- | --- |
| `format` | Literal `wpa2lab-eapol-v1` |
| `ssid` | Exact SSID string (UTF-8, 1–32 bytes) |
| `ap_mac`, `station_mac` | Distinct nonzero unicast MACs, 12 lowercase hex characters without separators |
| `anonce`, `snonce` | Matching exchange nonces, 64 lowercase hex characters each |
| `eapol` | Entire EAPOL message 2 **including its 4-byte EAPOL header**, lowercase hex; MIC bytes at offsets 81–96 set to zero |
| `mic` | Original MIC removed from that message, 32 lowercase hex characters |

The parser rejects extra fields, unknown versions, wrong lengths, inconsistent SNonce, a nonzero embedded MIC, and unsupported key-info flags. EAPOL versions 1/2, RSN descriptor 2, key-info `0x010a`, and key length 0/16 are accepted. The key-data length must match the remaining payload. JSON does not verify authorization, provenance, or that nonces came from the same exchange; a correctly formatted but inconsistent import normally yields no match.

The UI caps proof files at 16 KiB. EAPOL packets are bounded at 4 KiB. All request bodies are capped at 1 MiB, candidate lists at 10,000 entries, and each candidate at 63 printable ASCII characters. PCAP/PCAPNG, hashcat 22000, PMKID, and vendor-specific files are explicitly unsupported; no automatic capture or third-party authentication collection is implemented.

Proof exports are sensitive: someone holding them can test guesses offline. Setup passwords, PMKs, candidate lists, and matched passwords are not stored in SQLite. Projects, proof material, and matched results remain in session memory until **Clear projects and sensitive results** or shutdown. Python cannot guarantee immediate memory zeroization. Memory retention is bounded at 100 projects and 100 experiment results. History retains the latest 200 records in the UI; the SQLite file can be removed after shutdown to erase persistent history.

## Scanning and security analysis

The native integration uses `WlanOpenHandle`, `WlanEnumInterfaces`, `WlanGetInterfaceCapability`, `WlanScan`, `WlanGetAvailableNetworkList`, and `WlanGetNetworkBssList`. Driver metadata is read from the adapter's registry class key where available. It does not run commands, attempt connections, capture frames, or disconnect clients. Unsupported platforms return empty results and an explicit limitation.

Rows show observed BSSID, SSID, RSSI, signal quality, frequency, channel, adapter, adapter connection state, and the available Windows authentication/cipher classification. Classification is mapped from Windows' SSID-level available-network entries. If a name has conflicting classifications it is shown as unknown/ambiguous; this is not an independently parsed per-BSSID RSN assertion. Last request time is separate from the cached BSS `last_seen_windows_ticks` supplied by Windows. A scan request does not guarantee fresh observations. Driver manufacturer or WiFi standards are never inferred from names.

Legacy-risk notices are based only on the observed authentication/cipher classification. WPS, firmware, router brand, and monitor-mode capabilities remain **Not determined**. No advanced capture feature is advertised as supported. Router recommendations are general advice, not fabricated findings.

## Reports and access controls

HTML/JSON/CSV reports contain project, SSID, data source, method, candidate count, duration, status, recommendations, and the hardware snapshot **at export time**. Passwords are excluded by default. Including a session match requires both the inclusion checkbox and explicit confirmation; historical reports cannot recover discarded passwords. HTML is escaped and CSV formula prefixes are neutralized.

The backend binds exclusively to 127.0.0.1. All private API routes require the per-launch random token. Host checks, Origin checks, cross-site request rejection, a restrictive CSP, no CORS allowance, and non-caching responses guard browser access. Validation errors omit submitted values. There are no command execution or arbitrary file-path endpoints. This is a per-user local application, not a multi-user server; processes with access to the same OS account can access its local files and memory.

## Validation

`python -m pytest -q` exercises the published IEEE PMK vector, actual EAPOL MIC match/mismatch and independent derivation, bounded testing, deterministic cancellation, SQLite privacy, input/import validation, report escaping/sensitive confirmation, authenticated routes, origin/host guards, mock-scanner behavior, and shutdown callbacks. Mock scanners appear only in tests. These tests do not establish Windows hardware compatibility.

Optional Linux browser smoke (with Playwright and `/usr/bin/chromium` installed):

```sh
.venv/bin/python -m wpa2lab --no-browser --data-dir /tmp/wpa2lab-validation
# In another terminal, with Playwright available:
python3 tests/browser_smoke.py /tmp/wpa2lab-validation/instance.json
```

### Required Windows acceptance checks (not yet executed here)

1. Build on Windows 11 x64 and run tests. Verify the packaged EXE on a Windows machine with no Python/Node/WSL installed and with Internet disabled.
2. Double-click START, verify the browser opens only after readiness, inspect the 127.0.0.1-only listening address, relaunch START to reuse the instance, and check a conflicting process on port 8765 produces a clear failure. Test Ctrl+C, dashboard shutdown, and startup/crash errors.
3. With a real wireless adapter, scan without connecting to the lab router. Compare SSID, BSSID, authentication, cipher, RSSI, band/channel, connection state, and adapter details against Windows/router observations. Test disconnected radio, no adapter, Location denial, driver/service errors, and cached-scan behavior.
4. Generate data for `IEEE` / `password`, reject `incorrect`, then verify `password`. Import the exported proof into a new project and repeat. Separately validate an authorized genuine descriptor-v2 exchange if available; synthetic test success alone does not validate imported real captures.
5. Start a long bounded list, cancel, and verify terminal state and counts. Check no-match and malformed/unsupported import states.
6. Export each report type, confirm passwords are absent by default and included only after confirmation. Restart and verify history survives without passwords, while projects and sensitive results do not.

## Structure

`wpa2lab/crypto.py` handles verification and strict interchange parsing; `engine.py` manages jobs/history; `wifi.py` contains native scanning; `app.py` provides the protected local API; `__main__.py` handles startup/lifecycle; `static/` contains the frontend; `tests/` holds automated checks; `scripts/build-windows.ps1` creates the Windows release.
