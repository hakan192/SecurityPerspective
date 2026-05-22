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

## Upload certs into the running Nginx container

If the container is already running and you want to copy certs directly into it:

```bash
# 1) Find the nginx container name
docker compose ps nginx

# 2) Copy cert/key from host into the mounted path inside container
docker cp certs/server.crt <nginx_container_name>:/etc/nginx/ssl/server.crt
docker cp certs/server.key <nginx_container_name>:/etc/nginx/ssl/server.key

# 3) Enter the container (optional check)
docker exec -it <nginx_container_name> sh
ls -l /etc/nginx/ssl

# 4) Reload nginx so it picks up the new certificate
nginx -s reload
```

> Note: because `docker-compose.yml` already mounts `./certs:/etc/nginx/ssl:ro`, the preferred approach is to put files in the host `certs/` directory and restart/reload Nginx.
