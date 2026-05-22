FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY certs/tls.crt /etc/nginx/certs/tls.crt
COPY certs/tls.key /etc/nginx/certs/tls.key
