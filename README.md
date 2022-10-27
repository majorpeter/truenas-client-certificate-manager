# truenas-client-certificate-manager

Certificate Authority for mTLS applications in a home setup

## Use case

My home setup is based on [TrueNAS](https://www.truenas.com/). Some services I need to access from my phone &laptop on the go. I use mTLS to make sure I am the only one who has access.

TrueNAS and it's self-signed CA is used to issue client certificates. This application and its clients are used to renew those certificates automatically.

The clients can only renew their certificates when on the home network.

## Jail setup

There are several services in FreeBSD jails on the server. 2 of them are required for this setup:
* `proxy`: An nginx-based reverse proxy that is accessible only from LAN, manages HTTPS with [Let's Encrypt](https://letsencrypt.org/) etc. This jail runs the `truenas-client-certificate-manager`.
* `wanproxy`: Also an nginx-based reverse proxy. It is port-forwarded to the WAN interface and is **accessible remotely** via DDNS. Uses the same [Let's Encrypt](https://letsencrypt.org/) certs for HTTPS. Requires mTLS client certificate and instantly drops the connection if the client certificate is not provided or not accepted (i.e. _trust no one_ policy).

More information in [NGINX reverse proxy configuration](doc/nginx.md).

## Clients

* Linux/Node.js: [truenas-certificate-manager-client-node](https://github.com/majorpeter/truenas-certificate-manager-client-node)
* Android: TBD
