FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint-generate-cert.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-generate-cert.sh

CMD ["/usr/local/bin/docker-entrypoint-generate-cert.sh"]
