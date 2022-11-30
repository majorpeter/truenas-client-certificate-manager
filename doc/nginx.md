# NGINX reverse proxy configuration

## Proxy on WAN

The configuration is based on a [Let's Encrypt](https://letsencrypt.org/) setup. The notable changes are:
* `ssl_client_certificate`: The location of the CA crt file downloaded from TrueNAS Web UI.
* `ssl_verify_client`=`optional`: Setting to `optional` let's us handle the error as needed.
* `$ssl_client_verify != SUCCESS`: The client certificate is missing or not signed by our CA.
* `return 444`: Custom nginx return code that drops the connection and sends no HTTP response to the client (after the failed mTLS handshake).

### Example `nginx.conf` configuration

```
user  nobody;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;

events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  10;

    gzip  on;
    server_tokens off;  # hide version from 'Server:' header

    server {
        listen       443 ssl;
        server_name  my-service.example.com;

        ssl_certificate      /usr/local/etc/nginx/certs/fullchain.pem;
        ssl_certificate_key  /usr/local/etc/nginx/certs/privkey.pem;
        ssl_dhparam          /usr/local/etc/nginx/certs/dhparams.pem;

        ssl_client_certificate /usr/local/etc/nginx/certs/my-trusted-truenas-ca.crt;
        ssl_verify_client optional;

        ssl_session_cache    shared:SSL:5m;
        ssl_session_timeout  5m;
        ssl_session_tickets         off;
        ssl_stapling                on;
        ssl_stapling_verify         on;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;
        ssl_protocols TLSv1.2 TLSv1.3;

        proxy_ssl_server_name on;

        add_header Strict-Transport-Security    "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options              SAMEORIGIN;
        add_header X-Content-Type-Options       nosniff;
        add_header X-XSS-Protection             "1; mode=block";

        location / {
            proxy_pass http://192.168.0.100:8081/;

            proxy_set_header    X-Real-IP           $remote_addr;
            proxy_set_header    X-Forwarded-For     $proxy_add_x_forwarded_for;
            proxy_set_header    X-Forwarded-Proto   $scheme;
            proxy_set_header    Host                $host;
            proxy_set_header    X-Forwarded-Host    $host;
            proxy_set_header    X-Forwarded-Port    $server_port;

            # required for websocket
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        if ($ssl_client_verify != SUCCESS) {
            return 444;  # nothing is sent back
        }
    }
}
```

## _CA_ service on LAN

This configuration is very similar to the other one. The two differences are described below.

In order to identify the clients using _this_ application, we need to forward the fingerprint of the client cert to the server. Add this under `location /`:
```
proxy_set_header X-SSL-Client-SHA1 $ssl_client_fingerprint;
```

The `return 444;` part is optional in the `server` block.

Hint: `X-Forwarded-Host` is required for QR code login.
