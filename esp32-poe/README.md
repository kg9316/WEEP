# ESP32-POE PlatformIO Implementation

This PlatformIO project targets Olimex ESP32-POE using Arduino framework,
local Wi-Fi secrets, SPIFFS-hosted web UI, and an active WEEP WebSocket server.

## Board

- PlatformIO board: `esp32-poe`
- Chip family: ESP32 (WROOM-32 class)
- Intended flash target: 4 MB

## What is implemented

- Wi-Fi STA connection via local `include/secrets.h`
- HTTP UI at `/weep` (served from SPIFFS)
- WEEP WebSocket server at `ws://<device-ip>:81`
- SCRAM auth (`auth:scram-sha256`) on management channel
- `weep:file` profile: list, stat, upload, download, delete
- `weep:query` profile with JSON responses
- Binary framing + ACK flow for file transfer
- SD_MMC-backed file storage for file profile data
- mDNS advertisement (`_weep._tcp`) and discovery endpoint at `/weep/discover`
- Self-discovery fallback (device always listed even if mDNS browse omits self)

## Configure Wi-Fi (SSID/passord)

Copy `include/secrets.example.h` to `include/secrets.h` and set:

- `WIFI_SSID`
- `WIFI_PASS`

`include/secrets.h` is ignored by git so local credentials are not committed.

Example:

```cpp
#pragma once

constexpr const char* WIFI_SSID = "DIN_WIFI";
constexpr const char* WIFI_PASS = "DITT_PASSORD";
```

Tips:

- Do not put real Wi-Fi passwords in `src/main.cpp`.
- Keep only placeholders in `include/secrets.example.h`.
- Verify with `git status` before commit that `include/secrets.h` is not staged.

## Build and upload

From this folder:

```powershell
pio run
pio run -t upload
```

Upload SPIFFS content (`data/index.html`):

```powershell
pio run -t uploadfs
```

Monitor serial:

```powershell
pio device monitor
```

## Next steps

- Add `weep:stream` profile implementation on ESP32
- Optional: support single-port HTTP+WS deployment model on embedded target
- Improve discovery metadata parsing from mDNS TXT records (path/version/auth)
- Add broader interoperability tests against C# and Python implementations
