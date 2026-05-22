# TLS certificates for Nginx

Place TLS files here for local HTTPS support:

- `server.crt`
- `server.key`

If these files are absent, the custom Nginx image auto-generates a self-signed cert on startup so HTTPS can still start.

Example self-signed certificate generation:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/CN=localhost"
```

## Upload certs into the running Nginx container

If the container is already running and you want to copy certs directly into it:

```bash
# 1) Find the nginx container name
docker compose ps nginx

# 2) Copy cert/key from host into mounted path inside container
docker cp certs/server.crt <nginx_container_name>:/etc/nginx/ssl/server.crt
docker cp certs/server.key <nginx_container_name>:/etc/nginx/ssl/server.key

# 3) Enter the container (optional check)
docker exec -it <nginx_container_name> sh
ls -l /etc/nginx/ssl

# 4) Reload nginx so it picks up the new certificate
nginx -s reload
```

> Note: even though direct `docker cp` now works with the read-write mount, the preferred approach is still to place files in the host `certs/` directory so they persist and are versioned with your local environment setup.

### If you see `mounted volume is marked read-only`

That error means your container is running with a read-only bind mount for `/etc/nginx/ssl`.

Use one of these fixes:

1. **Recommended**: copy certs to the host project folder `./certs` and recreate nginx:
   ```bash
   cp securityperspective.crt certs/server.crt
   cp securityperspective.key certs/server.key
   docker compose up -d --force-recreate nginx
   ```
2. Restart with updated compose config that mounts `./certs:/etc/nginx/ssl` (read-write), then `docker cp` works.
