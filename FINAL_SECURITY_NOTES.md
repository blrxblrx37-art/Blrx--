# BLRX Final Security Notes

This build hardens the application against common web/API issues:
- HSTS and security headers
- CSRF origin checks and SameSite cookies
- API/request rate limits and body-size limits
- authentication/ownership checks on project APIs
- path traversal and symlink escape checks
- ZIP/TAR traversal, symlink and decompression-size limits
- safe GitHub archive extraction with file-count/size limits
- no shell=True in command execution
- package installers (pip/pip3/npm) disabled through the web command endpoint
- API account creation moved from GET to POST to avoid credentials in URLs

## Important isolation requirement
Users can upload and execute code by design. A Flask/Python process cannot safely isolate untrusted user code by itself. For strong multi-tenant security, run each user project in a separate container/VM with:
- non-root user
- read-only host filesystem
- dedicated writable volume
- CPU/RAM/PID limits
- network egress restrictions
- no Docker socket
- seccomp/AppArmor or equivalent
- separate process namespace

For volumetric DDoS, put the service behind a managed WAF/CDN (for example Cloudflare) and use the hosting provider's network-level DDoS protection.
