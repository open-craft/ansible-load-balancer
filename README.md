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

Architecture notes
------------------

Here's a summary what happens when a client updates a configuration fragment:

* A client (e.g. Ocim) generates a configuration fragment and a backend map,
  which are copied to the load balancing server via Ansible.

* On the haproxy server, there is a daemon called haproxy-configuration-watcher,
  which is watching for changes to the configuration fragments.  Whenever
  changes are detected, new versions of the configuration file and the backend
  map are generated from all the fragments, and haproxy is asked to reload its
  configuration.  (I skipped some details here – in fact the
  haproxy-configuration-watcher only creates a marker file, which is then seen
  by a cron job that is run once per minute.  This indirection was put in place
  as a precaution to prevent too frequent haproxy restarts.)

* The haproxy server runs a cron job every 5 minutes to detect whether it holds
  valid certificates for all domains listed in the backend map.  If a
  certificate is missing, it will automatically re-request one from Let's
  Encrypt.

* Another daemon called haproxy-cert-watcher will notice the new certificate,
  concatenate the relevant files and put them in the haproxy configuration
  directory, which in turn triggers a reload of haproxy via the
  haproxy-configuration-watcher.

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
that server.  DNS changes should already have propagated.

Create an inventory file containing your test server's hostname and IP address, e.g.,

    test.server.domain ansible_host=123.45.67.89

Then, from the `tests/` subdirectory, run:

    make test_integration TEST_HOSTS=hosts.test

Replace hosts.test with the path to the inventory file for your test server.

All tests can be run using

    make test TEST_HOSTS=hosts.test
