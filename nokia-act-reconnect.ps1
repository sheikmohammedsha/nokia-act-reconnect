<#
.SYNOPSIS
    JDownloader reconnect for Nokia / Alcatel-Lucent GPON ONT routers.

.DESCRIPTION
    Logs into the ONT web UI and reboots the device so the ISP issues a new
    public IP address - the "reconnect" that JDownloader needs.

    The web UI encrypts every POST body in JavaScript, so a normal
    LiveHeader/HTTP reconnect script cannot be used. This script reproduces
    the device's encryption (see crypto_page.js on the router):

        plaintext -> encrypted=1&ct=<AES-128-CBC/PKCS7>&ck=<RSA(PKCS1v15)>

        ct = Base64Url( AES-128-CBC( UTF8(plaintext), random 16-byte key, random 16-byte IV ) )
        ck = Base64UrlEscape( Base64( RSA_PKCS1_v1_5( "base64(key) base64(iv)" ) ) )

    The login request itself is accepted as plaintext (username + password +
    csrf_token + nonce read from the login page).

.PARAMETER RouterIp
    Address of the ONT web UI (default 192.168.0.1).

.PARAMETER Username
    Web UI username (default "admin").

.PARAMETER Password
    Web UI password. Prefer setting this in config.psd1 instead of on the
    command line, so it does not end up in shell history.

.PARAMETER Mode
    reboot  Reboot the ONT and wait for a new public IP (default).
    test    Verify login + encryption only, against a read-only endpoint.
            Does NOT reboot the router.

.PARAMETER InitialDelay
    Seconds to wait after the reboot command before polling for a new IP
    (default 20).

.PARAMETER Timeout
    Maximum seconds to keep polling for a new public IP (default 300).

.PARAMETER SkipIpCheck
    Return as soon as the reboot is acknowledged, without waiting for the new
    IP. Useful if JDownloader is configured to do the IP check itself.

.PARAMETER ConfigFile
    Path to a config.psd1 file. Defaults to config.psd1 next to this script.

.PARAMETER LogFile
    Optional path to also write the log to.

.PARAMETER Diag
    Print extra diagnostics (RSA key details).

.EXAMPLE
    .\nokia-reconnect.ps1 -Mode test
    Verify login + encryption without rebooting.

.EXAMPLE
    .\nokia-reconnect.ps1
    Reboot the ONT and wait for a new public IP.

.NOTES
    Tested on Windows PowerShell 5.1 (no modules required).
    Exit codes: 0 = success, 1 = failure, 2 = self-test failure.

    IMPORTANT: this device also exposes a PPPoE Disconnect/Dial API, but it is
    deliberately NOT used: dropping PPPoE can take the whole internet link down
    and leave it down. Rebooting is the safe, reliable reconnect.
#>
[CmdletBinding()]
param(
    [string]$RouterIp,
    [string]$Username,
    [string]$Password,

    [ValidateSet('reboot', 'test')]
    [string]$Mode = 'reboot',

    [int]$InitialDelay,
    [int]$Timeout,

    [switch]$SkipIpCheck,

    [string]$ConfigFile,
    [string]$LogFile,
    [switch]$Diag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# ---------------------------------------------------------------------------
# Settings (defaults < config.psd1 < command-line parameters)
# ---------------------------------------------------------------------------
$settings = @{
    RouterIp     = '192.168.0.1'
    Username     = 'admin'
    Password     = ''
    InitialDelay = 20
    Timeout      = 300
}

$cfgPath = $ConfigFile
if (-not $cfgPath) {
    $candidate = Join-Path $PSScriptRoot 'config.psd1'
    if (Test-Path -LiteralPath $candidate) { $cfgPath = $candidate }
}

if ($cfgPath) {
    if (-not (Test-Path -LiteralPath $cfgPath)) { throw "Config file not found: $cfgPath" }
    $cfg = Import-PowerShellDataFile -LiteralPath $cfgPath
    foreach ($key in $cfg.Keys) {
        if ($settings.ContainsKey($key)) { $settings[$key] = $cfg[$key] }
        else { Write-Warning "Ignoring unknown config key '$key'." }
    }
}

foreach ($key in @('RouterIp', 'Username', 'Password', 'InitialDelay', 'Timeout')) {
    if ($PSBoundParameters.ContainsKey($key)) { $settings[$key] = $PSBoundParameters[$key] }
}

$script:Diag = [bool]$Diag
$script:LogFilePath = $LogFile
$script:Base = "http://$($settings.RouterIp)"

function Write-Log([string]$Message) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    if ($script:LogFilePath) {
        try { Add-Content -LiteralPath $script:LogFilePath -Value $line } catch { }
    }
}

# ---------------------------------------------------------------------------
# ASN.1 / DER helper: build an RSA public key from the router's SPKI PEM
# ---------------------------------------------------------------------------
function Read-Tlv {
    param([byte[]]$Data, [int]$Pos)
    $tag = $Data[$Pos]; $Pos++
    $len = $Data[$Pos]; $Pos++
    if ($len -band 0x80) {
        $n = $len -band 0x7F; $len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $Data[$Pos]; $Pos++ }
    }
    [pscustomobject]@{ Tag = $tag; Len = $len; Start = $Pos }
}

function Get-RsaFromSpki {
    param([string]$Base64)
    $der = [Convert]::FromBase64String($Base64)

    # SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
    $outer = Read-Tlv $der 0
    $p = $outer.Start
    $alg = Read-Tlv $der $p
    $p = $alg.Start + $alg.Len
    $bit = Read-Tlv $der $p
    $inner = $bit.Start + 1                 # skip the "unused bits" octet
    $seq = Read-Tlv $der $inner
    $q = $seq.Start

    $modInt = Read-Tlv $der $q
    $mStart = $modInt.Start; $mLen = $modInt.Len
    while ($mLen -gt 1 -and $der[$mStart] -eq 0) { $mStart++; $mLen-- }   # strip DER sign byte
    $modulus = New-Object byte[] $mLen
    [Array]::Copy($der, $mStart, $modulus, 0, $mLen)

    $q = $modInt.Start + $modInt.Len
    $expInt = Read-Tlv $der $q
    $eStart = $expInt.Start; $eLen = $expInt.Len
    while ($eLen -gt 1 -and $der[$eStart] -eq 0) { $eStart++; $eLen-- }
    $exponent = New-Object byte[] $eLen
    [Array]::Copy($der, $eStart, $exponent, 0, $eLen)

    if ($script:Diag) {
        Write-Log ("RSA modulus: {0} bytes, exponent: {1} bytes" -f $modulus.Length, $exponent.Length)
    }

    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $parms = New-Object System.Security.Cryptography.RSAParameters
    $parms.Modulus = $modulus
    $parms.Exponent = $exponent
    $rsa.ImportParameters($parms)
    return $rsa
}

# ---------------------------------------------------------------------------
# Crypto: reproduces crypto_page.js
# ---------------------------------------------------------------------------
function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    ([Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
}

function New-EncryptedBody {
    param(
        [string]$Plaintext,
        [System.Security.Cryptography.RSACryptoServiceProvider]$Rsa
    )

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()

    $enc = $aes.CreateEncryptor()
    $pt = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
    $ct = $enc.TransformFinalBlock($pt, 0, $pt.Length)

    $ctB64Url = ConvertTo-Base64Url $ct

    $aesInfo = '{0} {1}' -f [Convert]::ToBase64String($aes.Key), [Convert]::ToBase64String($aes.IV)
    $rsaCt = $Rsa.Encrypt([System.Text.Encoding]::ASCII.GetBytes($aesInfo), $false)   # PKCS#1 v1.5
    $ck = [Convert]::ToBase64String($rsaCt).Replace('+', '-').Replace('/', '_').Replace('=', '.')

    "encrypted=1&ct=$ctB64Url&ck=$ck"
}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
function Get-Page {
    param([string]$Path)
    (Invoke-WebRequest -Uri "$script:Base$Path" -WebSession $script:Session `
        -UseBasicParsing -TimeoutSec 15).Content
}

function Post-Form {
    param([string]$Path, [string]$Body)
    Invoke-WebRequest -Uri "$script:Base$Path" -WebSession $script:Session -Method POST `
        -ContentType 'application/x-www-form-urlencoded; charset=UTF-8' `
        -Body $Body -UseBasicParsing -TimeoutSec 20
}

function Test-LoginPage([string]$Html) {
    ($Html -match 'id\s*=\s*"loginform"' -or $Html -match 'name="pswd"')
}

function Get-PublicIp {
    $urls = @(
        'https://api.ipify.org',
        'http://api.ipify.org',
        'https://checkip.amazonaws.com',
        'http://checkip.amazonaws.com',
        'http://icanhazip.com'
    )
    foreach ($url in $urls) {
        try {
            $ip = (Invoke-WebRequest -Uri $url -TimeoutSec 8 -UseBasicParsing).Content.Trim()
            if ($ip -match '^(\d{1,3}\.){3}\d{1,3}$') { return $ip }
        } catch { }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$script:Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$exitCode = 1

try {
    if ([string]::IsNullOrEmpty($settings.Password)) {
        throw 'No password configured. Set Password in config.psd1 or pass -Password.'
    }

    Write-Log "Connecting to $script:Base ..."
    $index = Get-Page '/'

    $pubkey = ([regex]'(?s)BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY').Match($index).Groups[1].Value
    $pubkey = ($pubkey -replace '\\', '' -replace '\s', '')

    if (Test-LoginPage $index) {
        $nonce = ([regex]'var nonce\s*=\s*"([^"]+)"').Match($index).Groups[1].Value
        $token = ([regex]'var token\s*=\s*"([^"]+)"').Match($index).Groups[1].Value
        if (-not $nonce -or -not $token) { throw 'Could not read nonce/token from the login page.' }

        $body = 'username={0}&password={1}&csrf_token={2}&nonce={3}' -f `
            [uri]::EscapeDataString($settings.Username), `
            [uri]::EscapeDataString($settings.Password), `
            [uri]::EscapeDataString($token), `
            [uri]::EscapeDataString($nonce)

        $resp = Post-Form '/login.cgi' $body
        $sid = $resp.Headers['X-SID']
        if ($resp.StatusCode -ne 299 -and -not $sid) {
            throw "Login failed (HTTP $($resp.StatusCode)). Check the username/password."
        }
        Write-Log 'Login OK.'
    } else {
        Write-Log 'Session already authenticated.'
    }

    if (-not $pubkey) { throw 'Public key not found on the page.' }
    $rsa = Get-RsaFromSpki $pubkey

    $rebootPage = Get-Page '/reboot.cgi'
    if (Test-LoginPage $rebootPage) { throw 'Session is not authenticated (reboot page redirected to login).' }
    $csrf = ([regex]'csrf_token=([A-Za-z0-9]+)').Match($rebootPage).Groups[1].Value
    if (-not $csrf) { throw 'Could not read csrf_token from the reboot page.' }

    if ($Mode -eq 'test') {
        # Read-only: exercise the encryption against the WAN status endpoint.
        $wanPage = Get-Page '/wan_config_glb.cgi'
        $csrfWan = ([regex]'csrf_token=([A-Za-z0-9]+)').Match($wanPage).Groups[1].Value
        $oid = ([regex]'_iid:(\d+)').Match($wanPage).Groups[1].Value
        if (-not $oid) { $oid = '10101' }

        $body = New-EncryptedBody "oid=$oid&csrf_token=$csrfWan" $rsa
        $r = Post-Form '/wan_config_glb.cgi?get_dial_status' $body
        if ($r.Content -match 'Bad request') {
            Write-Log 'Self-test: encryption was NOT accepted.'
            $exitCode = 2
        } else {
            Write-Log 'Self-test: login and request encryption are working.'
            $exitCode = 0
        }
    }
    else {
        $beforeIp = Get-PublicIp
        Write-Log "Public IP before reboot: $beforeIp"

        $body = New-EncryptedBody "data&csrf_token=$csrf" $rsa
        Write-Log 'Sending reboot request ...'
        $r = Post-Form '/reboot.cgi?reboot' $body
        if ($r.Content -notmatch 'done reboot') {
            throw "Reboot was not acknowledged by the device: $($r.Content)"
        }
        Write-Log 'Reboot acknowledged by the device.'

        if ($SkipIpCheck) {
            Write-Log 'SkipIpCheck set - done.'
            $exitCode = 0
        }
        else {
            Write-Log "Waiting ${InitialDelay}s, then polling for a new public IP (max $($settings.Timeout)s) ..."
            Start-Sleep -Seconds $InitialDelay

            $deadline = (Get-Date).AddSeconds($settings.Timeout)
            $newIp = $null
            while ((Get-Date) -lt $deadline) {
                $nowIp = Get-PublicIp
                if ($nowIp -and ((-not $beforeIp) -or ($nowIp -ne $beforeIp))) { $newIp = $nowIp; break }
                Start-Sleep -Seconds 5
            }

            if ($newIp) {
                Write-Log "Reconnect complete. New public IP: $newIp"
                $exitCode = 0
            } else {
                Write-Log "No new public IP detected within $($settings.Timeout)s."
                $exitCode = 1
            }
        }
    }
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    $exitCode = 1
}

exit $exitCode
