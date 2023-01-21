FROM golang AS build
COPY *.go go.mod go.sum /tmp/dow-proxy/
RUN cd /tmp/dow-proxy && go build

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=build /tmp/dow-proxy/dow-proxy /usr/bin/dow-proxy

EXPOSE 53/udp
EXPOSE 53/tcp
CMD ["dow-proxy", "-verbose", "-upstream", "wss://dow-proxy.addr.tools"]
