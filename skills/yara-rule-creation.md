# Skill: YARA Rule Creation

> Guide to writing robust, performant YARA rules for malware detection, threat hunting, and artifact classification.

---

## YARA Rule Anatomy

```yara
import "pe"
import "math"

rule MalwareFamily_Variant_Author : tag1 tag2 {
    meta:
        author      = "analyst-name"
        date        = "2026-03-17"
        description = "Detects MalwareFamily variant X"
        reference   = "https://example.com/report"
        tlp         = "WHITE"
        mitre_att   = "T1059.001"
        severity    = "high"
        hash        = "sha256_of_sample"

    strings:
        $str1 = "unique_string" ascii wide
        $hex1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 }
        $re1  = /https?:\/\/[a-z0-9\-\.]+\.evil\.com/ nocase
        $pdb  = "C:\\Users\\Attacker\\source" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (2 of ($str*) or $pdb) and
        pe.imports("kernel32.dll", "VirtualAlloc") and
        math.entropy(0, filesize) > 7.0
}
```

---

## String Types & Modifiers

| Type | Syntax | Performance |
|------|--------|-------------|
| Text | `"string"` | Fast |
| Text wide | `"string" wide` | Fast |
| Hex | `{ DE AD BE EF }` | Fast |
| Regex | `/pattern/` | **Slow — use sparingly** |

| Modifier | Effect | Notes |
|----------|--------|-------|
| `ascii` | ASCII match (default) | Explicit is better |
| `wide` | UTF-16LE match | Common in Windows malware |
| `nocase` | Case-insensitive | Slight performance cost |
| `fullword` | Whole words only | **Avoid on strings < 5 chars** |
| `xor` | XOR-encoded match | `xor(0x01-0xFF)` for all keys |
| `base64` | Base64-encoded match | YARA 4.0+ |
| `private` | Don't report in output | Reduce noise |

### ⚠️ Critical Rules

- Strings ≥ 6 bytes for reliable matching
- Combine multiple strings with `2 of`, `3 of` conditions
- Use hex patterns for opcodes (more stable than text)
- Use `??` wildcards and `[N-M]` jumps in hex patterns
- **Never** rely on a single string for detection
- **Never** use common library strings as sole indicators
- **Avoid** regex when text/hex patterns suffice

---

## Condition Patterns

### Basics

```yara
condition:
    all of them                     // All strings
    any of them                     // Any string
    2 of ($str*)                    // 2 of str-prefixed strings
    #str1 > 5                       // String count > 5
    $str1 at 0                      // At specific offset
    $str1 in (0..1024)              // Within range
```

### File Type Magic Numbers

```yara
// PE:    uint16(0) == 0x5A4D
// ELF:   uint32(0) == 0x464C457F
// PDF:   uint32(0) == 0x25504446
// OLE:   uint32(0) == 0xE011CFD0
// ZIP:   uint16(0) == 0x4B50
// Mach-O: uint32(0) == 0xFEEDFACE or 0xFEEDFACF
```

---

## Module Usage

### PE Module

```yara
import "pe"
condition:
    pe.is_pe and
    pe.imports("kernel32.dll", "VirtualAlloc") and
    pe.imports("kernel32.dll", "CreateRemoteThread") and
    pe.number_of_signatures == 0 and
    for any s in pe.sections : (s.name == ".rsrc" and s.entropy > 7.0)
```

### Math Module

```yara
import "math"
condition:
    math.entropy(0, filesize) > 7.5     // Likely packed
    math.entropy(filesize/2, filesize/2) > 7.5  // High-entropy overlay
```

### Hash Module

```yara
import "hash"
condition:
    for any s in pe.sections : (
        s.name == ".text" and
        hash.sha256(s.raw_data_offset, s.raw_data_size) == "abc123..."
    )
```

---

## Performance Optimization

**Short-circuit: put fast, failing checks first.**

```yara
// GOOD order:
condition:
    uint16(0) == 0x5A4D and       // 1. Magic number (instant)
    filesize < 5MB and             // 2. Size check (instant)
    pe.imports("ws2_32.dll") and   // 3. Import scan (fast)
    2 of ($str*) and               // 4. String scan (medium)
    math.entropy(0, filesize) > 7  // 5. Entropy (slow)
```

### Anti-Patterns

- ❌ Regex with unbounded repetition: `/.{1,1000}/`
- ❌ `fullword` on 3-character strings
- ❌ No type/size pre-filtering before string scan
- ❌ Importing unused modules
- ❌ `for all` loops over large sets (use `for any`)

---

## Naming Convention

```
<family>_<variant>_<detection_type>.yar

emotet_loader_strings.yar
cobalt_strike_beacon_config.yar
webshell_generic_php.yar
apt29_wellmess_network.yar
```

Tags: space-separated, lowercase — `malware trojan rat apt29`

---

## Testing Methodology

```bash
# 1. Compile — check syntax
yarac rules.yar rules.yarc

# 2. Test against known-bad (should match)
yara -r -s rules.yar /path/to/malware_samples/

# 3. Test against known-good (should NOT match)
yara -r rules.yar /usr/bin/
yara -r rules.yar /Applications/

# 4. Performance benchmark
time yara -r rules.yar /path/to/large_sample_set/

# 5. Python integration test
python3 -c "
import yara
rules = yara.compile('rules.yar')
for m in rules.match('/path/to/sample'):
    print(f'{m.rule}: {m.tags} — {m.meta}')
"
```

---

## Rule Templates

### Malware Detection

```yara
rule TEMPLATE_Malware {
    meta:
        author = "NAME" | date = "YYYY-MM-DD"
        description = "Detects FAMILY based on DESCRIPTION"
        severity = "high" | mitre_att = "TXXXX"
        hash = "SHA256"
    strings:
        $s1 = "unique_string_1" ascii
        $s2 = "unique_string_2" wide
        $h1 = { 48 8B ?? ?? ?? ?? ?? 48 85 C0 }
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of them
}
```

### Webshell Detection

```yara
rule TEMPLATE_Webshell_PHP {
    meta:
        description = "PHP webshell with eval/exec patterns"
        severity = "critical" | mitre_att = "T1505.003"
    strings:
        $php  = "<?php" nocase
        $ev1  = "eval(" nocase
        $ev2  = "assert(" nocase
        $ex1  = "system(" nocase
        $ex2  = "exec(" nocase
        $ex3  = "passthru(" nocase
        $ob1  = "base64_decode(" nocase
        $ob2  = "gzinflate(" nocase
        $in1  = "$_GET" | $in2 = "$_POST" | $in3 = "$_REQUEST"
    condition:
        $php and filesize < 500KB and
        (1 of ($ev*) or 1 of ($ex*)) and
        (1 of ($ob*) or 1 of ($in*))
}
```

### Packed Executable Detection

```yara
import "pe"
import "math"

rule TEMPLATE_Packed_PE {
    meta:
        description = "Packed/crypted PE with high entropy and RWX sections"
        severity = "medium" | mitre_att = "T1027.002"
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        math.entropy(0, filesize) > 7.2 and
        for any s in pe.sections : (
            (s.characteristics & 0xE0000000) == 0xE0000000 and
            s.entropy > 7.0 and s.raw_data_size > 1024
        ) and
        pe.number_of_imports < 10
}
```
