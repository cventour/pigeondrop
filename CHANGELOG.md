# What's new

## v1.2.0 — 14 October 2026

- New: **Scan over ICAPS.** Settings has a TLS option for ICAP servers that only accept encrypted connections. The server's certificate is checked, and the test explains when it is not trusted.

## v1.1.1 — 2 October 2026

- Fixed: **Settings could not be saved when Pigeonhole runs as a hardened systemd service.** They are now kept in the service's own state folder, and if a folder cannot be written the message says what to change.

## v1.1.0 — 2 October 2026

- New: **Scan uploads with an ICAP server.** Open Settings, enter the server, and every upload is checked before it appears in the list. Files the scanner blocks are discarded and the threat is named.
- New: **Test connection.** Settings can check a server before you save it, including whether it is able to scan.
