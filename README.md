# RBPO — Windows Tray Application + Service

This repository contains the **client side** of a Windows antivirus solution built as a university project.
The architecture consists of two executables: a system-tray GUI (`rbpo-app.exe`) and a background Windows service (`rbpo-service.exe`) that communicate through local RPC (ALPC).

The service also talks to a remote **Spring Boot backend** (`rbpo_backend`) over HTTPS for authentication, license management, and signature updates.

```
rbpo-front     ← you are here (client)
rbpo_backend   ← Java / Spring Boot server
```

---

## Branches (incremental tasks)

Each branch adds a new layer on top of the previous one.

| Branch | What it covers |
|--------|---------------|
| `main`   | Current working state (tasks 1-5 merged). |
| `zad-1`  | Qt6 tray app: PNG icon, system tray, context menu, `QMenuBar` File→Exit, single-instance via named mutex. |
| `zad-2`  | Windows service: launch GUI into every user session, `CreateProcessAsUserW` with `SecurityImpersonation`, RPC `ncalrpc` endpoint for remote stop, PowerShell install script. |
| `zad-3`  | Auth & licensing: JWT tokens kept **only in memory**, HTTPS POSTs to backend, GUI login/activation forms, background license worker polling every 5s. |
| `zad-4`  | Antivirus engine: file / directory / drive scanning, Aho-Corasick automaton, scheduled scans, directory monitoring via `ReadDirectoryChangesW`, all RPC calls guarded by `LicenseGate()`. |
| `zad-5`  | Binary storage: custom `RBDB v1` format on disk, HMAC-SHA256 manifest (`RBMF v1`), automatic backup before updates, periodic refresh from `GET /api/signatures`. |

---

## Project layout

- `src/main.cpp` — Qt6 GUI (tray icon, login form, activation screen, AV dashboard).
- `src/service/service_main.cpp` — Service entry point (`ServiceMain`), RPC server loop, session enumeration, GUI spawning.
- `src/service/state.cpp` — Token & license workers: login, refresh, activate, check-license loop.
- `src/service/http_client.h/cpp` — WinHTTP wrapper for HTTPS REST calls.
- `src/service/av_engine.h/cpp` — Core scanner, Aho-Corasick tree, `ScanFile`, `ScanDirectory`, `ScanAllDrives`.
- `src/service/av_db_io.h/cpp` — Binary serialization (`avdb.bin`), manifest signing / verification, backup/restore.
- `src/rpc/rbpo_rpc.idl` — MIDL interface definition (compiled into `rpc_gen/`).
- `src/rbpo_rpc_constants.h` — Service name (`RBPOService`), endpoint name (`RBPOServiceEndpoint`), error codes.
- `scripts/install_service.ps1` — Admin script: stop old service → delete → create → start.

Service name on the system: **RBPOService**.  
RPC transport: **ALPC** (`ncalrpc:`), endpoint name: **RBPOServiceEndpoint**.

---

## Task 3 — Authentication & licensing flow

### Where credentials live

- **GUI** never stores passwords. It sends them once over RPC to the service.
- **Service** keeps `accessToken` and `refreshToken` **only in RAM** (`state.cpp`).
- On service stop everything is wiped. On next start the user must log in again.
- `productId` is persisted to the registry (under `HKLM`) so the license check worker knows which product to validate.

### License check worker

A background thread (`LicenseWorker`) wakes every 5 seconds and:
1. Builds a JSON body with `{ deviceMac, productId }`.
2. POSTs it to `/api/licenses/check` with the current `Bearer` token.
3. If HTTP **200** → parses the signed ticket, stores expiry date, sets `licenseHeld = true`.
4. If HTTP **404** → no license; if HTTP **403** → blocked by admin.
5. If the ticket says `blocked=true` or the expiry date has passed, the GUI automatically switches back to the activation screen.

### Known backend quirk we handled

The backend returns `productId` as a **number** (`1`) inside the `ticket` object, while some implementations send it as a string. Our `ParseSignedTicket` falls back to numeric extraction and defaults to `"1"` if the field is missing entirely.

---

## Task 4 — Antivirus engine

### In-memory signature database

```
std::map<uint64_t, std::vector<AvRecord>>
  key   → first 8 bytes of the signature (little-endian uint64)
  value → list of records sharing that prefix
```

Per-record fields:
- `prefix`        — same 8-byte prefix as the map key.
- `sigLen`        — total signature length in bytes.
- `sigHash`       — SHA-256 of the *entire* signature bytes.
- `offsetBegin`   — earliest allowed file offset for a match (`-1` = any).
- `offsetEnd`     — latest allowed file offset for a match (`-1` = any).
- `type`          — `0` = PE, `1` = Script.
- `recordSig`     — SHA-256 over `prefix|sigLen|sigHash|offsetBegin|offsetEnd|type` (integrity check).

The `std::map` gives us **O(log K)** prefix lookup.

### Basic scan algorithm

1. Open the file, cursor = 0.
2. Read 8 bytes, convert to `uint64_t` key.
3. Look up the key in the map. If nothing found → shift cursor by 1 byte, repeat.
4. For every candidate record with that prefix (cheapest tests first):
   - Does the detected file type match `type`?
   - Does cursor lie inside `[offsetBegin, offsetEnd]`?
   - Read the remaining `sigLen - 8` bytes.
   - Compute SHA-256 of `prefix_bytes + extra_bytes`.
   - Compare with `sigHash`.
5. Discard mismatches. If at least one record survives → **threat detected**.

### Aho-Corasick (optional fast path)

During `AvLoad` we also build an AC automaton from the *real* signature bytes. `ScanStream` can then do a single pass over the file in **O(N + M)** instead of the sliding-window approach above. When the automaton reports a hit we still verify type and offset constraints.

### File type detection

| Rule | Assigned type |
|------|--------------|
| Extension is `.py`, `.ps1`, `.js`, `.vbs` | Script |
| First bytes are `MZ` | PE |
| Anything else | Script |

### Built-in test signatures

| 16-byte payload | Type | Trigger |
|----------------|------|---------|
| `RBPOTESTVRS1.000` | PE | File contains these bytes AND starts with `MZ` |
| `#RBPOTESTVRS2.00` | Script | File contains these bytes AND has `.py`/`.ps1` extension |

### RPC surface exposed by the service

Required:
- `RBPO_GetAvDbInfo` — returns release date + record count.
- `RBPO_ScanFile` — scan a single file path.
- `RBPO_ScanDirectory` — recursive scan.

Optional (extra credit):
- `RBPO_ScanAllDrives` — all fixed drives.
- `RBPO_SetScanSchedule` / `RBPO_ClearScanSchedule` / `RBPO_GetScheduleResults`
- `RBPO_AddMonitorDirectory` / `RBPO_RemoveMonitorDirectory` / `RBPO_GetMonitorResults`

All scanning RPCs first call `LicenseGate()`. If the license is not active the call returns `RBPO_ERR_NO_LICENSE`.

---

## Task 5 — Binary database format on disk

Four files live next to `rbpo-service.exe`:

| File | Purpose |
|------|---------|
| `avdb.bin` | Active signature database |
| `avdb.manifest` | HMAC-SHA256 manifest protecting `avdb.bin` |
| `avdb.bin.bak` / `avdb.manifest.bak` | Backup created before every update |
| `avdb.default.bin` / `avdb.default.manifest` | Hard-coded fallback database (2 test signatures) |

### `avdb.bin` — RBDB v1 layout

```
[4]   magic      'R','B','D','B'
[2]   version    LE uint16 = 1
[4]   count      LE uint32 — number of records
[2]   dateLen    LE uint16 — length of UTF-8 release date string
[N]   date       UTF-8 release date
[32]  dataHash   SHA-256 over the entire record section
------ record section ------
for each record:
  [8]   prefix        LE uint64
  [4]   sigLen        LE uint32
  [1]   sigHashLen    0 or 32
  [N]   sigHash       bytes (if len > 0)
  [8]   offsetBegin   LE int64
  [8]   offsetEnd     LE int64
  [1]   type          0=PE, 1=Script
  [1]   hasRemainderHash
  [4]   sigBytesLen   LE uint32
  [N]   sigBytes      raw signature bytes
  [2]   nameLen       LE uint16
  [N]   threatName    UTF-8
  [32]  recordSig     SHA-256(prefix|sigLen|sigHash|offsetBegin|offsetEnd|type)
```

### `avdb.manifest` — RBMF v1 layout

```
[4]   magic        'R','B','M','F'
[2]   version      LE uint16 = 1
[32]  fileHash     SHA-256(avdb.bin contents)
[32]  manifestSig  HMAC-SHA256(key, magic|version|fileHash)
```

### Startup load sequence

1. If `avdb.default.bin` is missing → generate it from the built-in test signatures.
2. Try to verify `avdb.manifest`:
   - Valid → load `avdb.bin`, validate each record signature.
   - If some records are invalid and network is up → force an update from backend.
   - Invalid manifest + network + valid token → force an update.
3. If step 2 fails → try loading `avdb.bin.bak` (backup).
4. If backup also fails → fall back to `avdb.default.bin`.

### Automatic update loop

`AvDbStartUpdate(3600)` launches a thread that sleeps 3600 seconds between cycles:
1. Copy current `avdb.bin` → `avdb.bin.bak` and `avdb.manifest` → `avdb.manifest.bak`.
2. Download fresh signatures via `GET /api/signatures`.
3. Serialize new `avdb.bin` + `avdb.manifest`.
4. If write fails → restore from `.bak`.

---

## Backend endpoints used

All calls go to port **8081** (HTTP by default). Override via environment variables:
- `RBPO_BACKEND_HOST`
- `RBPO_BACKEND_PORT`
- `RBPO_BACKEND_USE_TLS`

| Method | Path | Body highlights |
|--------|------|----------------|
| POST | `/api/auth/login` | `{ username, password }` |
| POST | `/api/auth/refresh` | `{ refreshToken }` |
| GET  | `/api/auth/me` | — |
| POST | `/api/licenses/activate` | `{ activationKey, deviceMac, deviceName }` |
| POST | `/api/licenses/check` | `{ deviceMac, productId }` |
| GET  | `/api/signatures` | Full signature database (for updates) |

---

## Building on Windows

Prerequisites: Visual Studio 2022, Qt6, CMake.

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Outputs:
- `build/Release/rbpo-app.exe`
- `build/Release/rbpo-service.exe`

Both must reside in the **same directory** at runtime.

### Manual service registration

```bat
sc create RBPOService binPath= "C:\path\to\rbpo-service.exe" start= demand DisplayName= "RBPO Service"
sc start RBPOService
```

### Manual removal

```bat
sc stop RBPOService
sc delete RBPOService
```

### Scripted install (recommended)

Run **as Administrator**:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_service.ps1
```

The script stops/deletes any old service instance, re-creates it, and starts it.

---

## Demo guide

See `DEMO_GUIDE.md` for a step-by-step walkthrough with exact Postman requests and expected GUI behaviour for each task.
