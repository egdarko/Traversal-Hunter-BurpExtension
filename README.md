# 📂 Traversal Hunter

**An autonomous Path Traversal vulnerability scanner for Burp Suite — built on the Montoya API.**

> Developed by **egdarko**

Traversal Hunter is a Burp Suite extension that automates the detection of **Local File Inclusion (LFI)** and **Path Traversal** vulnerabilities. It performs intelligent reconnaissance, filter fingerprinting, adaptive payload mutation, and multi-phase scoring to confirm exploitable traversal flaws with minimal user interaction.

---

## Download

Get the latest `TraversalHunter.jar` from the [Releases](../../releases) page.

---

## Installation

### Prerequisites

- **Burp Suite Professional or Community Edition** (2023.x or later)
- **Java JDK 11+** installed

### Load into Burp Suite

1. Open **Burp Suite** → **Extensions** tab → **Installed** sub-tab
2. Click **Add**
3. Set **Extension type** to `Java`
4. Click **Select file...** and choose `TraversalHunter.jar`
5. Click **Next** → **Close**

You should see the **"Traversal Hunter"** tab appear. The output log will show:

```
Traversal Hunter Loaded
Right-click in ANY tabs: Proxy, Repeater, Logger, Target, Inspector
```

---

## Usage

### Method 1: Context Menu (Recommended)

1. **Intercept** or browse to a request with URL parameters, body parameters, or cookies
2. **Right-click** the request in any Burp tab:
   - **Proxy** → Intercept / HTTP History
   - **Repeater**
   - **Logger**
   - **Target** → Site map
3. Select **"Traversal Hunter Scan"**

The extension automatically:
- Captures the selected request(s)
- Profiles baseline behavior
- Tests all parameters with all payloads
- Escalates depth with adaptive strategies
- Reports findings in real-time

### Method 2: Scan Last Request

---

## UI Controls

| Control | Description |
|---------|-------------|
| **Max Depth** | Maximum traversal depth for escalation (1–25) |
| **Threads** | Concurrent scan threads (1–10) |
| **Delay (ms)** | Base delay between requests |
| **Mode** | Scan behavior: STEALTH / BALANCED / AGGRESSIVE / HYBRID (Auto) |
| **STOP SCAN** | Immediately halt the current scan |
| **Scan Last Request** | Scan the most recently intercepted proxy request |

---

## Scan Phases

```
[PHASE 1] Baseline Profiling
    └── Capture normal response (status, length, timing, entropy)

[PHASE 2] Reflection Analysis  
    └── Detect how parameters are reflected in responses

[PHASE 3] Filter Fingerprinting
    └── Identify input filters: stripping, URL decode, normalization, WAF

[PHASE 4] Custom Payload Testing
    └── Test all parameters with user-defined payload list

[PHASE 5] Adaptive Depth Escalation
    └── Escalate traversal depth with selected bypass strategies

[PHASE 6] Final Analysis
    └── Report best finding, send to Repeater if confirmed
```

---

## Confidence Levels

| Level | Score | Icon | Action |
|-------|-------|------|--------|
| **NONE** | 0 | — | No finding |
| **LOW** | 1–2 | [L] | Minor anomaly |
| **MEDIUM** | 3–4 | [M] | Suspicious behavior |
| **HIGH** | 5–7 | [H] | Strong indicator |
| **CRITICAL** | 8–11 | [C] | Very likely vulnerable |
| **CONFIRMED** | 12+ | [OK] | Vulnerability confirmed → Auto-sent to Repeater |

---

## Scoring Indicators

The extension scores responses based on:

| Indicator | Points | Description |
|-----------|--------|-------------|
| `root:x:` | +6 | /etc/passwd content detected |
| `[extensions]` | +5 | Windows win.ini detected |
| `daemon:` / `/bin/bash` | +3 | Unix system files |
| `boot loader` / `[fonts]` | +3 | Windows system files |
| Large length diff (>200) | +3 | Significant response size change |
| Status 200 (from non-200) | +3 | Unexpected success |
| Status 500 | +2 | Server error (possible path handling issue) |
| `Permission denied` | +3 | File exists but access blocked |
| `No such file` | +2 | File path processed but missing |
| High timing diff (>1000ms) | +3 | Potential file read delay |
| Entropy shift (>1.0) | +2 | Response content type changed |

---

## Mutation Strategies

| Strategy | Trigger | Payload Example |
|----------|---------|---------------|
| **BASIC** | Always | `../../../etc/passwd` |
| **DOT_OVERFLOW** | Stripping filter detected | `....//....//etc/passwd` |
| **URL_ENCODE** | Single-decode filter | `%2e%2e%2f%2e%2e%2fetc/passwd` |
| **DOUBLE_ENCODE** | Double-decode filter | `%252e%252e%252fetc/passwd` |
| **WINDOWS** | Always | `..\..\..\windows\win.ini` |
| **ABSOLUTE** | Always | `/etc/passwd` |

---

## Custom Payloads

Edit payloads directly in the **Custom Payloads** text area:

- One payload per line
- Lines starting with `#` are comments
- Use **Load from File** / **Save to File** for persistence
- Click **Reset Defaults** to restore built-in payloads

### Default Payloads Include:

- Classic traversal (`../../../etc/passwd`)
- Double-dot bypass (`....//....//....//etc/passwd`)
- URL encoding (`%2e%2e%2f`, `%252e%252e%252f`)
- Null byte truncation (`../../../etc/passwd%00.png`)
- Windows paths (`..\..\..\windows\win.ini`)
- Absolute paths (`/etc/passwd`)

---

## Mode Behavior

| Mode | Delay | Jitter | Use Case |
|------|-------|--------|----------|
| **STEALTH** | Base × 3 (min 500ms) | 100–500ms | WAF-protected targets, rate-limited APIs |
| **BALANCED** | Base delay | 0–200ms | General testing |
| **AGGRESSIVE** | Base ÷ 2 (min 50ms) | 0–50ms | Internal testing, no WAF |
| **HYBRID** | Auto-selected | Auto-selected | Automatically chooses based on filter fingerprint |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No intercepted request yet" | Browse the target through Burp Proxy first, then click "Scan Last Request" |
| "No parameters found in request" | The target may use path segments. Add a query parameter in Repeater (e.g., `?file=test.jpg`) |
| WAF blocks all requests | Switch to **STEALTH** mode and increase delay |
| False positives | Check the **Score** column; LOW/MEDIUM findings may need manual verification |
| Extension won't load | Ensure you're using Java 11+ and Burp Suite 2023.1+ |

---

## Demo

### Scanning from Repeater
```
1. Send request to Repeater
2. Right-click request → "Traversal Hunter Scan"
3. Watch real-time results in the extension tab
4. CONFIRMED findings auto-appear in Repeater
```

### Scanning from Proxy History
```
1. Find request in Proxy → HTTP History
2. Right-click → "Traversal Hunter Scan"  
3. Extension profiles, tests, and reports automatically
```

---

## API Compatibility

| Extension Version | Montoya API | Burp Suite |
|-------------------|-------------|------------|
| 1.0.x | 2026.4 | 2023.1+ |

---

## Disclaimer

This tool is intended for **authorized security testing only**. Always ensure you have explicit permission before scanning any target. The authors assume no liability for misuse or damage caused by this software.

---

<p align="center">
  <b>⭐ Star this repo if it helped you find a bug!</b>
</p>
