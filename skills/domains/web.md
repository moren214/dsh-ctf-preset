# Domain: Web Exploitation

- Static source first: trace routes, middlewares, templates, deserialization sinks, and unsafe imports with `trace_flask_route` / workspace file readers.
- Live probing: use `http_request` (with named `cookie_jar` for session isolation, `follow_redirects`, multipart upload) against `ctf_instance` / `ctf_arena` authorized origins.
- Browser-rendered SPAs / XSS / DOM sinks: use `browser_session` (`open`, `dom`, `cookies`, `storage`, `network`, `evaluate`, `click`, `fill`, `upload_file`), always respecting CSP and closing idle sessions.
- Common checks: SQLi, SSTI (`{{7*7}}`, Python MRO gadgets), SSRF, prototype pollution, JWT `alg=none`/weak HMAC (`crypto_solver` `solve`), path traversal, deserialization.
