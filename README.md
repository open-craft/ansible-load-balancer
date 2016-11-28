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
  certbot's standalone web server.  Certificate management is fully automatic
  and transparent to any client.

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
   balancing server.

2. Create a configuration fragment with the desired backend configuration, e.g.

        backend be_example_com
            stick-table type string len 128 size 20k expire 12h
            stick on req.cook(sessionid)
            server srv_example_com example.com:80 check

3. Create a backend map fragment containing lines with mappings from domain
   names to backends, e.g.

        example.com be_example_com
        www.example.com be_example.com

4. Copy the configuration and backend map fragments to temporary files on the
   server and run

        haproxy-config apply <fragment_name> <tmp_config_fragment> <tmp_backend_map_fragment>

   This will replace any fragments with the given fragment name.  To remove the
   fragment again, use

        haproxy-config remove <fragment_name>

Running the tests
-----------------

To lint the Python code, run

    make test_prospector

To run the unit tests, change to the `tests/` subdirectory and run

    make test_unit

To run the integration test playbook in `tests/integration.yml`, you need a
server with a vanilla Ubuntu 16.04 image, and at least one DNS name pointing to
that server.  DNS changes should already have propagated.  The run

    make test_integration TEST_DOMAIN=test.server.domain

from the `tests/` subdirectory. Replace test.server.domain with the DNS name of
your test server.

All tests can be run using

    make test TEST_DOMAIN=test.server.domain
