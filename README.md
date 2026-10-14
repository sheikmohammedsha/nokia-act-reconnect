# nokia-act-reconnect

**JDownloader reconnect for Nokia / Alcatel-Lucent GPON "Home Gateway" ONT routers** (the
white ONTs handed out by ACT Fibernet and similar ISPs).

The script logs into the router's web UI and **reboots the ONT**, which makes the ISP hand
out a **new public IP** — exactly what JDownloader needs to work around *"IP already in
use"* / *"wait 60 minutes"* limits.

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Highlights

- Works where a normal **LiveHeader/HTTP** script cannot — see [Why an external script](#why-an-external-script).
- **Zero dependencies**: Windows PowerShell 5.1 (built into Windows). No Python, no modules, no admin rights.
- **No credentials in the repo** — configure once in `config.psd1` (git-ignored) or pass parameters.
- Re-reads the login token/nonce and encryption key on every run, so it survives reboots and firmware quirks.
- Waits until the **new public IP is actually live**, so JDownloader's own IP check passes immediately.
- Ships a `.bat` wrapper for one-line JDownloader configuration.

## Requirements

- Windows 10/11 with Windows PowerShell 5.1 (default) — no extra software.
- Your PC must be connected to the ONT's LAN (the web UI at `192.168.0.1`).
- The ONT's web UI login.

> Tested against a Nokia/Alcatel-Lucent **GPON Home Gateway** as deployed by ACT Fibernet,
> but the approach applies to other ONTs that use the same encrypted `reboot.cgi` API.

## Quick start

1. Copy `config.example.psd1` to `config.psd1` and fill in your login:

   ```powershell
   Copy-Item config.example.psd1 config.psd1
   ```

   ```powershell
   # config.psd1
   @{
       RouterIp     = '192.168.0.1'
       Username     = 'admin'
       Password     = 'YOUR-PASSWORD'
       InitialDelay = 20
       Timeout      = 300
   }
   ```

2. **Verify login + encryption without rebooting** (safe):

   ```powershell
   .\nokia-reconnect.bat -Mode test
   ```

3. **Do a real reconnect** (reboots the ONT; internet drops for ~2–3 minutes):

   ```powershell
   .\nokia-reconnect.bat
   ```

## Files

| File | Purpose |
|---|---|
| `nokia-reconnect.ps1` | The reconnect script (login → reboot → wait for new IP). |
| `nokia-reconnect.bat` | Thin wrapper so JDownloader (or Task Scheduler) can call it easily. |
| `config.example.psd1` | Template configuration. Copy to `config.psd1` (git-ignored). |
| `LICENSE` | MIT. |

## Configuration

Settings are resolved in this order (later wins):

1. Built-in defaults
2. `config.psd1` next to the script (or `-ConfigFile <path>`)
3. Command-line parameters

| Parameter | Default | Description |
|---|---|---|
| `-RouterIp` | `192.168.0.1` | ONT web UI address. |
| `-Username` | `admin` | Web UI username. |
| `-Password` | *(empty)* | Web UI password. Prefer `config.psd1` over the command line. |
| `-Mode` | `reboot` | `reboot` or `test` (test = verify only, no reboot). |
| `-InitialDelay` | `20` | Seconds to wait after the reboot before the first IP check. |
| `-Timeout` | `300` | Maximum seconds to wait for the new public IP. |
| `-SkipIpCheck` | off | Return right after the reboot is acknowledged (let JDownloader do the IP check). |
| `-ConfigFile` | `config.psd1` | Alternate config file path. |
| `-LogFile` | *(none)* | Also append the log to this file. |
| `-Diag` | off | Print extra diagnostics. |

**Exit codes:** `0` = success, `1` = failure, `2` = self-test failure.

## JDownloader setup

In JDownloader 2: **Settings → Reconnect**, tick *Reconnect enabled*, then pick a method.

There are two relevant methods. Use either one — the labels below are the exact options in
the reconnect-method dropdown.

### Option A — *External Tool Reconnect* (recommended)

Runs one external program with a list of parameters.

- **Command:** `C:\Tools\nokia-act-reconnect\nokia-reconnect.bat`
- **Parameter (1 parameter per line):** *(leave empty)*

Or, calling PowerShell directly (use the full path to `powershell.exe`):

- **Command:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Parameter (1 parameter per line):**

  ```
  -NoProfile
  -ExecutionPolicy
  Bypass
  -File
  "C:\Tools\nokia-act-reconnect\nokia-reconnect.ps1"
  ```

### Option B — *External Batch Reconnect*

Runs a batch of commands through an interpreter.

- **Interpreter:** `cmd.exe /c`
- **Batch Script:** `"C:\Tools\nokia-act-reconnect\nokia-reconnect.bat"`
- **Start in (application folder):** `C:\Tools\nokia-act-reconnect`

### Timing values (either method)

Rebooting the ONT takes a couple of minutes, so give JDownloader room:

| Field | Value |
|---|---|
| Timeout for IP-check / Waittime for first IP Check | `5` |
| Max retries | `1`–`2` |
| Timeout for new IP | `300` |
| Timeout for command execution | `600` |

Then click **Test reconnect** / **Do reconnect now**.

> The script already blocks until the new IP is confirmed, so the "Timeout for command
> execution" must be **larger** than the script's runtime (~1–6 minutes).

### Prefer the script to return fast?

Add `-SkipIpCheck` in the parameter list. The script will exit `0` as soon as the ONT
acknowledges the reboot, and JDownloader's *Timeout for new IP* does the waiting instead.

## Why an external script?

The ONT's web UI **encrypts every POST body in JavaScript** before sending it:

```
plaintext  ->  encrypted=1&ct=<AES-128-CBC/PKCS7>&ck=<RSA(PKCS1v15) of the AES key + IV>
```

- `ct` = Base64Url( AES-128-CBC( UTF8(plaintext), random 16-byte key, random 16-byte IV ) )
- `ck` = Base64UrlEscape( Base64( RSA_PKCS1_v1_5( "<base64 key> <base64 iv>" ) ) )

A JDownloader **LiveHeader/HTTP** script can send raw requests but cannot run AES/RSA, so it
cannot produce the encrypted reboot body. `nokia-reconnect.ps1` reproduces the device's
`crypto_page.js` encryption exactly, using only .NET classes. (The login request is
accepted as plaintext, so only the action bodies need to be encrypted.)

## How it works

1. `GET /` — read the form's `nonce`, `csrf_token` and the RSA public key.
2. `POST /login.cgi` — plaintext login; the server answers `HTTP 299` with an `X-SID` header and sets the session cookie.
3. `GET /reboot.cgi` — read that page's `csrf_token`.
4. Encrypt `data&csrf_token=<token>` and `POST /reboot.cgi?reboot`.
5. Poll a public-IP service until the **public IP changes** (or `-Timeout` is reached).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Login failed` | Wrong username/password, or a different firmware. Re-check `config.psd1`. |
| `Bad request for invalid parameter` | Login token/csrf mismatch — usually a stale session or changed firmware. Re-run; if it persists, check that you can log in manually at `http://192.168.0.1`. |
| `Could not read csrf_token` | The device returned the login page instead of `reboot.cgi` (session expired). Re-run the script. |
| Reconnect "succeeds" but no new IP | Some ISPs occasionally hand back the same IP. Raise **Max retries** in JDownloader. |
| HTTPS / TLS errors on the IP check | The script already tries several HTTP and HTTPS IP services. Check your firewall/proxy. |
| `running scripts is disabled on this system` | The `.bat` already passes `-ExecutionPolicy Bypass`. |
| Nothing happens | Make sure the PC is on the ONT's LAN and `http://192.168.0.1` opens in a browser. |

## FAQ

**Why does the router reboot instead of just re-dialling PPPoE?**
The ONT does expose a PPPoE Disconnect/Dial API, but dropping PPPoE can take the whole
internet link down and leave it down, so this project deliberately uses the safe
**reboot** path. A reboot reliably yields a new session and a new public IP.

**Why does the reconnect take 2–3 minutes?**
That is the ONT's own reboot + PPPoE re-authentication time — it is not the script. The
script actively polls every 5 seconds and returns the moment the new IP appears, so it adds
no avoidable delay.

**Will I always get a new IP?**
Usually yes (verified repeatedly). If your ISP reassigns the same IP, JDownloader reports a
failed reconnect and can retry — raise *Max retries*.

**Do I need administrator rights?**
No.

**Does it store my password?**
It reads it from `config.psd1`, which is git-ignored and never leaves your machine. The
repository contains no credentials.

## Disclaimer

Rebooting the ONT briefly interrupts **all** internet access on that line. Use at your own
risk. This project is not affiliated with Nokia, Alcatel-Lucent, ACT Fibernet, or
JDownloader. Device firmware varies — verify with `-Mode test` first.

## License

[MIT](LICENSE)
