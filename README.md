# dow-proxy
A DNS over WebSocket proxy
## How to build
Requires [Go](https://go.dev/)
```
$ go build
```
Or use the `Dockerfile` with slight modifications to the passed options.
## Usage
```
dow-proxy [OPTIONS]

Options:
  -insecure
    	Skip server certificate verification for upstream encrypted connections
  -listen [IP]:port
    	Listening [IP]:port. IP is optional, leave empty to listen on all interfaces. (default ":53", ":80", or ":443" depending on server and TLS options)
  -max-ws number
    	Maximum number of WebSockets to serve simultaneously (default 50)
  -requests-per-ws number
    	Maximum number of open DNS requests per WebSocket. Additional requests will be refused. (default 50)
  -server
    	Listen for WebSocket connections instead of plaintext DNS. Unless a TLS certificate and key are provided, the WebSocket connections will be unencrypted.
  -timeout duration
    	Maximum allowed time duration to wait for network activities (default 5s)
  -tls-cert file
    	TLS certificate file path for encrypting WebSocket connections in server mode
  -tls-key file
    	TLS private key file path for encrypting WebSocket connections in server mode
  -udp-buffer bytes
    	EDNS UDP buffer size in bytes (default 1232)
  -upstream server
    	Upstream DNS server IP address or URL
  -verbose
    	Verbose output
  -ws-buffer bytes
    	WebSocket read and write buffer size in bytes (default 512)
```
## Examples
Start a server to host secure WebSocket connections, forwarding to Cloudflare's 1.1.1.1 using DNS over TLS.
```
./dow-proxy -server -listen :443 -tls-cert "/path/to/server.crt" -tls-key "/path/to/server.key" -upstream tls://1.1.1.1
```
Start a client to forward local plaintext DNS requests to a server using DNS over WSS (WebSocket Secure).
```
./dow-proxy -listen 127.0.0.1:53 -upstream wss://my-server
```
## Use behind a reverse proxy
Start a server to host insecure WebSocket connections.
```
./dow-proxy -server -listen 127.0.0.1:8000 -upstream tls://1.1.1.1
```
Example reverse proxy configuration for nginx:
```
http {

    map $http_upgrade $connection_upgrade {
        default upgrade;
        "" close;
    }

    server {

        location / {
            proxy_http_version 1.1;
            proxy_pass http://127.0.0.1:8000;
            proxy_read_timeout 1h;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
```
## Public test server
A public server is available at `wss://dow-proxy.addr.tools`. It forwards all requests to Cloudflare's 1.1.1.1.
```
./dow-proxy -upstream wss://dow-proxy.addr.tools
```
