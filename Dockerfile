FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY sbserver /usr/local/bin/sbserver

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sbserver"]
