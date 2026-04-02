# WEEP Web UI Testing Guide

This document explains how to test the Web UI in `js/index.html` against the local WEEP server.

## Prerequisites

- .NET 8 SDK installed (`dotnet --version`)
- PowerShell or terminal
- This repository cloned locally

## 1. Start the server

From the repository root, run:

```powershell
dotnet run --project csharp/Weep.TestRunner/Weep.TestRunner.csproj -- --server-only --port 9443
```

Expected startup lines include:

- `Kestrel listening on http://localhost:9443`
- `Web UI:    http://localhost:9443/`
- `Endpoint:  http://localhost:9443/weep`

Keep this terminal running while testing.

## 2. Open the Web UI

Open:

- http://localhost:9443/

The page title should show **WEEP File Browser**.

## 3. Connect and authenticate

In the left sidebar use:

- Server URL: `ws://localhost:9443/weep`
- Username: `admin`
- Password: `admin`
- Auth mechanism: `Auto (prefer SCRAM)`

Click **Connect**.

Expected result:

- Header status turns connected
- Activity log shows greeting and authentication success
- Root file list appears

## 4. Manual functional checks

### Browse

- Click folders to enter them
- Use breadcrumb links to navigate back to root

Expected: path updates and list refreshes without errors.

### Upload

- Click **Upload here**
- Pick one or more small files

Expected:

- Progress bar moves to 100%
- File(s) appear in the current listing
- Log shows successful transfer

### Download

- Click **Download** on a file row

Expected: browser downloads the selected file.

### Disconnect / reconnect

- Click **Disconnect**, then **Connect** again

Expected: clean disconnect and successful reconnect.

## 5. Quick endpoint verification (optional)

Use this command to confirm the page is serving:

```powershell
$r = Invoke-WebRequest -Uri http://localhost:9443/ -UseBasicParsing
$r.StatusCode
```

Expected output: `200`

## 6. Run protocol test runner (optional)

This validates C# client/server protocol behavior, including auth and transfers:

```powershell
dotnet run --project csharp/Weep.TestRunner/Weep.TestRunner.csproj -- --server --port 9443
```

Expected summary:

- `Passed: 22`
- `Failed: 0`

## Troubleshooting

- Port already in use:
  - Run with a different port, for example `--port 9555`
  - Update UI Server URL to match, for example `ws://localhost:9555/weep`
- Cannot connect from UI:
  - Ensure server terminal is still running
  - Check the endpoint line printed by server startup
- Authentication fails:
  - Use username/password `admin` / `admin` (default in test runner)
- No files shown:
  - The server uses the repository `files/` directory as storage root

## Stop the server

In the server terminal, press `Ctrl+C`.
