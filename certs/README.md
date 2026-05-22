# TLS certificates for Nginx

Place TLS files here for local HTTPS support:

- `server.crt`
- `server.key`

Example self-signed certificate generation:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/CN=localhost"
```
