# Security hardening

This build includes:
- HSTS and common security headers when served over HTTPS.
- Secure, HttpOnly, SameSite session cookies.
- Password hashing with PBKDF2-SHA256; legacy plaintext passwords are migrated on startup.
- Public `/api/create` is disabled unless an authenticated admin session or `X-HOSTING-BOT-KEY` is supplied.
- File-management API routes verify login, ownership and server validity.
- Path traversal protection for file operations and ZIP extraction.
- ZIP extraction limits for file count and uncompressed size.
- Login/API rate limiting.
- `shell=True` removed from the web command endpoint and shell metacharacters are rejected.
- Passwords are not returned by the admin user-list API.

## Required environment variables

Set a strong random `SECRET_KEY` in production.

Set `ADMIN_PASSWORD` when creating a new deployment with no existing `users.json`.

If the Telegram/bot API is used, set a long random `HOSTING_BOT_API_KEY` and send it as:
`X-HOSTING-BOT-KEY`.

## Important limitation

This application intentionally runs user-uploaded Python/Node projects on the same host process account. No Flask-level patch can make that a secure multi-tenant sandbox. For untrusted users, run each project inside a separate container/VM with restricted filesystem, network, CPU, memory and privileges.
