FROM alpine:3.20
RUN apk add --no-cache nsd bind-tools
ENTRYPOINT ["/usr/sbin/nsd"]
CMD ["-d", "-c", "/config/nsd.conf"]
