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

To run the unit tests, change to the `tests/` subdirectory and run

    PYTHONPATH=../templates python3 -m unittest test_manage_certs.py

You can run the integration test playbook in `tests/integration.yml` against a
server with a vanilla Ubuntu 16.04 image.  You need at least one DNS name
pointing at the server, and DNS changes should already have propagated.

1. Create a Python virtualenv and activate it.

2. Change to the `tests/` directory and run `pip install -r requirements.txt` to
   install Ansible and further required packages.

3. Run the playbook using

        ansible-playbook -vvv -i test.server.domain, integration.yml

   Replace test.server.domain by the DNS name of your test server, but make sure
   to keep the trailing comma.
