# What's new

## v1.5.1 — 16 October 2026

- Changed: **Pigeonhole's code now lives at github.com/cventour/pigeondrop.** Old links and install commands still work.

## v1.5.0 — 16 October 2026

- New: **Run it with npx.** `npx pigeondrop` starts Pigeonhole in the folder you are in, with nothing to install. Its files and settings stay in that folder.

## v1.4.0 — 16 October 2026

- New: **Pigeonhole has an icon.** It shows in the browser tab and beside the page heading.

## v1.3.0 — 14 October 2026

- New: **Verify the certificate can be turned off.** For a scanner with a self-signed certificate on a network you trust, the connection is still encrypted.
- Changed: **TLS failures say why.** Test connection, uploads and Save explain what is wrong with the scanner's certificate or connection and what to change.

## v1.2.0 — 14 October 2026

- New: **Scan over ICAPS.** Settings has a TLS option for ICAP servers that only accept encrypted connections. The server's certificate is checked, and the test explains when it is not trusted.

## v1.1.1 — 2 October 2026

- Fixed: **Settings could not be saved when Pigeonhole runs as a hardened systemd service.** They are now kept in the service's own state folder, and if a folder cannot be written the message says what to change.

## v1.1.0 — 2 October 2026

- New: **Scan uploads with an ICAP server.** Open Settings, enter the server, and every upload is checked before it appears in the list. Files the scanner blocks are discarded and the threat is named.
- New: **Test connection.** Settings can check a server before you save it, including whether it is able to scan.
