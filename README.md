Ansible role for an haproxy-based load balancing server
=======================================================

This role deploys haproxy configured as a load balancer for multiple domains,
possibly with multiple servers for each domain name.  It allows dynamic
reconfiguration of backends, and is intended to be used with the OpenCraft
Instance Manager, though nothing in this role is specific to this use case.

Requirements
------------

The role can be run against a server with a vanilla Ubuntu 16.04 image.

Features
--------

* All plain HTTP requests are redirected to HTTPS.

* HTTPS connections are decrypted on the load balancer.

* SSL certificates are managed on the load balancer using the certbot client for
  Let's Encrypt.  ACME challenges for domain verification are routed to
  certbot's standalone web server.

* Backends for HTTPS connections are chosen based on the Host header of the
  request.  Backends and mappings of domain names to backends can be added
  dynamically.

* The haproxy configuration is assembled from multiple fragments.  Updating a
  fragment automatically triggers a regeneration of the configuration and a
  reload of haproxy.  Reloads use haproxy's graceful reload feature and are
  rate-limited to once per minute.

Adding backends
---------------

To add a new backend, perform the following steps:

1. Create CNAME DNS records for all desired domain names pointing to the load
   balancing server, and wait for the DNS changes to propagate.

2. Log into the load balancing server and run

        letsencrypt certonly \
            -d <domain> [ -d <domain> ... ] \
            --email <email> \
            --authenticator standalone \
            --standalone-supported-challenges http-01 \
            --http-01-port 8080 \
            --non-interactive \
            --agree-tos \
            --keep \
            --expand

   If you are obtaining the certificate just for testing purposes, also add

            --staging

   to obtain an SSL certificate for your domains.  The server will take care of
   renewing the certificate automatically.

3. Add an haproxy configuration fragment to /etc/haproxy/conf.d/ containing the
   desired backend configuration, e.g.

        backend be_example_com
            stick-table type string len 128 size 20k expire 12h
            stick on req.cook(sessionid)
            server example.com:80 check

4. Add a backend map fragment to /etc/haproxy/backends/, containing lines with
   mappings from domain names to backends, e.g.

        example.com be_example_com
        www.example.com be_example.com
