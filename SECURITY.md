# Security policy

relay. v0.11.1 is a **prototype for fictitious test data**, not an audited school production system.

## Supported versions
Only the latest GitHub version receives fixes. Do not expose the application directly to the Internet.

## Reporting
Please report security vulnerabilities privately to the repository maintainer using GitHub private vulnerability reporting (if enabled). **Do not publish exploits or real personal data in public issues.**

## Known limitations
- SQLite data on disk is not encrypted.
- The default Docker service runs as root inside its container for compatibility with existing bind-mounted data directories. Running as a non-root user requires verified ownership/permissions migration and is not enabled automatically.
- Inline JavaScript and CSS remain in use; CSP therefore allows `unsafe-inline`.
- Authentication is single-admin; IP-based throttling can affect users sharing a tunnel/proxy.
- Backup restoration and physical barcode scanner have not been validated in an end-to-end test.
- No independent security audit or dependency vulnerability scan has been completed.

## Changes in v0.11.1
- Hardened CSV export against formula injection including leading whitespace.
- Server-side request body limit of 1 MiB for writes (CSV parser retains its own 300 KB limit).
- Added automated CSV regression tests to GitHub Actions.
- Preserved database layout, login and lending flows.
