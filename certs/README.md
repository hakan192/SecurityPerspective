# TLS certificate files for Nginx

Place your TLS certificate and private key in this directory before building the containers:

- `tls.crt` - PEM-encoded certificate chain
- `tls.key` - PEM-encoded private key

These files are copied into the Nginx image at build time so HTTPS is available immediately when the container starts.
