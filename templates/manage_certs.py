#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Certificate management for haproxy load balancing server.

This script is intended to be run as a cron job on a frequent basis.  It scans
the haproxy backend map for active domain names, determines which ones have
valid certificates and requests new certificates for the remaining domains via
Let's Encrypt.  It finds unused certificates in the haproxy configuration,
removes them and disables the associated Let's Encrypt renewal configuration.
"""

import collections
import json
import pathlib
import socket
import ssl
import subprocess

import OpenSSL.crypto

SERVER_FQDN = "{{ ansible_fqdn }}"
HAPROXY_BACKEND_MAP = "{{ LOAD_BALANCER_BACKEND_MAP }}"
HAPROXY_CERTS_DIR = pathlib.Path("{{ LOAD_BALANCER_CERTS_DIR }}")
CONTACT_EMAIL = "{{ OPS_EMAIL }}"
LETSENCRYPT_USE_STAGING = json.loads("{{ LETSENCRYPT_USE_STAGING }}".lower())
LETSENCRYPT_FAKE_CERT = "{{ LETSENCRYPT_FAKE_CERT }}"


def get_all_domains():
    """Get a list of all configured domains from the haproxy backend map."""
    domains = collections.OrderedDict()
    with open(HAPROXY_BACKEND_MAP) as backend_map:
        for line in backend_map:
            line = line.strip()
            if line and not line.startswith("#"):
                domain, backend = line.split(None, 1)
                domains[domain] = backend
    return domains


def get_ssl_context():
    """Return a standard SSL context."""
    if not get_ssl_context.ctx:
        get_ssl_context.ctx = ssl.create_default_context()
        get_ssl_context.ctx.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
        if LETSENCRYPT_USE_STAGING:
            get_ssl_context.ctx.load_verify_locations(LETSENCRYPT_FAKE_CERT)
    return get_ssl_context.ctx

get_ssl_context.ctx = None


def has_valid_cert(domain, ctx=None):
    """Verify that localhost serves a valid SSL certificate for the given domain."""
    # The easiest and most reliable way to determin whether we have a valid
    # certificate for a given hostname is to connect to haproxy on port 443 and
    # transfer the hostname we want to enquire about in the SNI extension.
    # Python's SSL implementation verifies whether the certificate is valid and
    # matches the hostname in its default configuration.  This way, we see all
    # certificates that are actually served, including any that might not have
    # been retrieved via Let's Encrypt, and get the matching right for wildcard
    # certificates.  This makes sure we only request new certificates when
    # needed.
    if ctx is None:
        ctx = get_ssl_context()
    conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    try:
        conn.connect(("localhost", 443))
    except ssl.SSLError:
        return False
    else:
        return True
    finally:
        conn.close()


def has_valid_dns_record(domain):
    """Determine whether the domain name resolves to this server."""
    try:
        domain_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return False
    if not has_valid_dns_record.external_ip:
        result = subprocess.run(["host", SERVER_FQDN], stdout=subprocess.PIPE)
        if result.returncode:
            # TODO: log error
            raise Exception("Cannot resolve FQDN to an IP address.")
        unused, external_ip = result.stdout.strip().rsplit(None, 1)
        has_valid_dns_record.external_ip = external_ip.decode("ascii")
    return domain_ip == has_valid_dns_record.external_ip

has_valid_dns_record.external_ip = None


def get_all_domains():
    """Get a list of all configured domains from the haproxy backend map."""
    domains = collections.OrderedDict()
    with open(HAPROXY_BACKEND_MAP) as backend_map:
        for line in backend_map:
            line = line.strip()
            if line and not line.startswith("#"):
                domain, backend = line.split(None, 1)
                domains[domain] = backend
    return domains


def get_certless_domains(all_domains):
    """Get a list of domain names that need a new certificate."""
    return [
        domain for domain in all_domains
        if has_valid_dns_record(domain) and not has_valid_cert(domain)
    ]


def request_cert(domains, staging=LETSENCRYPT_USE_STAGING):
    """Request a new SSL certificate for the listed domains"""
    command = [
        "letsencrypt", "certonly",
        "--email", CONTACT_EMAIL,
        "--authenticator", "standalone",
        "--standalone-supported-challenges", "http-01",
        "--http-01-port", "8080",
        "--non-interactive",
        "--agree-tos",
        "--keep",
        "--expand"
    ]
    if staging:
        command.append("--staging")
    for domain in domains:
        command += ["-d", domain]
    result = subprocess.run(command)
    # TODO: Log output on error, log success message on success
    return result.returncode


def request_new_certs(all_domains):
    """Request new certificates for all domains that need one."""
    certless_domains = get_certless_domains(all_domains)
    domains_by_backend = {}
    for domain in certless_domains:
        backend = all_domains[domain]
        domains_by_backend.setdefault(backend, []).append(domain)
    for domains in domains_by_backend.values():
        try:
            request_cert(domains)
        except Exception as exc:  # pylint: disable=broad-except
            # TODO: log exception
            pass


def get_dns_names(cert):
    """Retrieve the DNS names for the given certificate."""
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            dns_names = []
            for component in ext._subjectAltNameString().split(", "):  # pylint: disable=protected-access
                name_type, name = component.split(":", 1)
                if name_type == "DNS":
                    dns_names.append(name)
            return dns_names
    for label, value in cert.get_subject().get_components():
        if label == b"CN":
            return [value.decode("utf8")]
    raise ValueError("the certificate does not contain a valid Common Name, "
                     "nor valid Subject Alternative Names")


def remove_cert(cert_path):
    """Delete the certificate pointed to by the path, and deactivate renewal."""
    cert_path.unlink()
    renewal_config = pathlib.Path("/etc/letsencrypt/renewal", cert_path.stem + ".conf")
    if renewal_config.is_file():
        renewal_config.rename(renewal_config.with_suffix(".disabled"))


def clean_up_certs(all_domains):
    """Remove old certificate files from /etc/letsencrypt."""
    active_domains = set(all_domains)
    for cert_path in HAPROXY_CERTS_DIR.glob("*.pem"):
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_path.read_bytes())
        try:
            dns_names = set(get_dns_names(cert))
        except ValueError as exc:
            # TODO: log error, no DNS name found
            continue
        if any("*" in name for name in dns_names):
            # Contains a wildcard.  Not from Let's Encrypt, so we don't touch it.
            continue
        if dns_names.isdisjoint(active_domains):
            # Certificate does not serve any active domains, so we can remove it
            remove_cert(cert_path)


def main():
    """Perform all operations."""
    all_domains = get_all_domains()
    request_new_certs(all_domains)
    clean_up_certs(all_domains)


if __name__ == "__main__":
    main()
