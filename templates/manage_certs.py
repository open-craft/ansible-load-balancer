#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Certificate management for haproxy load balancing server.

This script is intended to be run as a cron job on a frequent basis.  It scans
the haproxy backend map for active domain names, determines which ones have
valid certificates and requests new certificates for the remaining domains via
Let's Encrypt.  It finds unused certificates in the haproxy configuration,
removes them and disables the associated Let's Encrypt renewal configuration.
"""

import argparse
import collections
import logging.handlers
import itertools
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys

import OpenSSL.crypto


logger = logging.getLogger()


def get_all_domains(config):
    """Get a list of all configured domains from the haproxy backend map."""
    # Use integers as dummy backend IDs for the additional domains, to ensure they can
    # never collide with actual backend names.
    domains = collections.OrderedDict(zip(config.additional_domain, itertools.count()))
    with config.haproxy_backend_map.open() as backend_map:
        for line in backend_map:
            line = line.strip()
            if line and not line.startswith("#"):
                domain, backend = line.split(None, 1)
                domains[domain.lower()] = backend
    return domains


def get_ssl_context(config):
    """Return a standard SSL context."""
    if not get_ssl_context.ctx:
        get_ssl_context.ctx = ssl.create_default_context()
        get_ssl_context.ctx.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
        if config.letsencrypt_use_staging and config.letsencrypt_fake_cert is not None:
            get_ssl_context.ctx.load_verify_locations(config.letsencrypt_fake_cert)
    return get_ssl_context.ctx

get_ssl_context.ctx = None


def has_valid_cert(config, domain, ctx=None):
    """Verify that localhost serves a valid SSL certificate for the given domain."""
    # The easiest and most reliable way to determine whether we have a valid
    # certificate for a given hostname is to connect to haproxy on port 443 and
    # transfer the hostname we want to enquire about in the SNI extension.
    # Python's SSL implementation verifies whether the certificate is valid and
    # matches the hostname in its default configuration.  This way, we see all
    # certificates that are actually served, including any that might not have
    # been retrieved via Let's Encrypt, and get the matching right for wildcard
    # certificates.  This makes sure we only request new certificates when
    # needed.
    if ctx is None:
        ctx = get_ssl_context(config)
    conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    try:
        conn.connect(("localhost", 443))
    except (ssl.SSLError, ssl.CertificateError):
        return False
    else:
        return True
    finally:
        conn.close()


def has_valid_dns_record(config, domain):
    """Determine whether the domain name resolves to this server."""
    try:
        domain_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return False
    return domain_ip == config.server_ip or domain_ip.split(".", 1)[0] == "127"


def get_certless_domains(config, all_domains):
    """Get a list of domain names that need a new certificate."""
    result = []
    for domain in all_domains:
        valid_dns = has_valid_dns_record(config, domain)
        logger.debug(
            "The DNS record for the domain %s %s to this server.",
            domain,
            "points" if valid_dns else "does not point",
        )
        valid_cert = has_valid_cert(config, domain)
        logger.debug(
            "This server %s a valid cert for the domain %s.",
            "has" if valid_cert else "does not have",
            domain,
        )
        if valid_dns and not valid_cert:
            result.append(domain)
    return result


def request_cert(config, domains):
    """Request a new SSL certificate for the listed domains."""
    command = [
        "letsencrypt", "certonly",
        "--email", config.contact_email,
        "--authenticator", "standalone",
        "--standalone-supported-challenges", "http-01",
        "--http-01-port", "8080",
        "--non-interactive",
        "--agree-tos",
        "--keep",
        "--expand",
        "--force-renew",
    ]
    if config.letsencrypt_use_staging:
        command.append("--staging")
    for domain in domains:
        command += ["-d", domain]
    result = subprocess.run(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    if result.returncode == 0:
        logger.info(
            "Successfully obtained a new certificate from Let's Encrypt for these domains:\n    %s",
            "\n    ".join(domains),
        )
    else:
        logger.error(
            "Failed to obtain a new certificate for these domains:\n    %s\n%s",
            "\n    ".join(domains),
            result.stderr,
        )
    return result.returncode


def request_new_certs(config, all_domains):
    """Request new certificates for all domains that need one."""
    certless_domains = get_certless_domains(config, all_domains)
    domains_by_backend = {}
    for domain in certless_domains:
        backend = all_domains[domain]
        domains_by_backend.setdefault(backend, []).append(domain)
    for domains in domains_by_backend.values():
        try:
            request_cert(config, domains)
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "An exception occurred when trying to obtain a new certificate for these domains:\n"
                "    %s",
                "\n    ".join(domains),
            )


def get_dns_names(cert):
    """Retrieve the DNS names for the given certificate."""
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            dns_names = []
            for component in ext._subjectAltNameString().split(", "):
                name_type, name = component.split(":", 1)
                if name_type == "DNS":
                    dns_names.append(name.lower())
            return dns_names
    for label, value in cert.get_subject().get_components():
        if label == b"CN":
            return [value.decode("utf8").lower()]
    raise ValueError("the certificate does not contain a valid Common Name, "
                     "nor valid Subject Alternative Names")


def remove_cert(cert_path):
    """Delete the certificate pointed to by the path, and deactivate renewal.

    Only certificates with a Let's Encrypt renewal configuration are removed,
    since we want to keep certificates that have been manually added.
    """
    domain = cert_path.stem
    renewal_config = pathlib.Path("/etc/letsencrypt/renewal", domain + ".conf")
    if not renewal_config.is_file():
        logger.info(
            "The certificate %s is not used by any active backend domain.  "
            "However, there is no Let's Encrypt configuration for it, so it is "
            "not automatically removed.",
            cert_path,
        )
        return
    logger.info(
        "The certificate %s is not used by any active backend domain.  "
        "It is removed and the renewal configuration is disabled.",
        cert_path,
    )
    cert_path.unlink()
    renewal_config.unlink()
    shutil.rmtree("/etc/letsencrypt/live/" + domain, ignore_errors=True)
    shutil.rmtree("/etc/letsencrypt/archive/" + domain, ignore_errors=True)


def clean_up_certs(config, all_domains):
    """Remove old certificate files from /etc/letsencrypt."""
    active_domains = set(all_domains)
    for cert_path in config.haproxy_certs_dir.glob("*.pem"):
        if cert_path.name in config.keep_certificate:
            continue
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_path.read_bytes())
        try:
            dns_names = set(get_dns_names(cert))
        except ValueError:
            logger.error("Unable to determine domain names for certificate %s.", cert_path)
            continue
        if any("*" in name for name in dns_names):
            # Contains a wildcard.  Not from Let's Encrypt, so we don't touch it.
            continue
        if dns_names.isdisjoint(active_domains):
            # Certificate does not serve any active domains, so we can remove it.
            remove_cert(cert_path)


def configure_logger(logger_, log_level):
    """Configure the logger to log to the syslog with the given log level."""
    logger_.setLevel(log_level)
    handler = logging.handlers.SysLogHandler(address='/dev/log')
    handler.setFormatter(logging.Formatter("%(filename)s: %(message)s"))
    logger_.addHandler(handler)
    stderr_handler = logging.StreamHandler()
    stderr_handler.setLevel(logging.ERROR)
    logger_.addHandler(stderr_handler)


class ArgumentParser(argparse.ArgumentParser):
    """Argument parser with more useful config file syntax."""

    def convert_arg_line_to_args(self, arg_line):
        """Treat each space-separated word as a separate argument."""
        return arg_line.split()


def parse_command_line(args):
    """Parse the command-line arguments."""
    parser = ArgumentParser(fromfile_prefix_chars="@")
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--haproxy-backend-map", required=True, type=pathlib.Path)
    parser.add_argument("--haproxy-certs-dir", required=True, type=pathlib.Path)
    parser.add_argument("--contact-email", required=True)
    parser.add_argument("--letsencrypt-use-staging", action="store_true")
    parser.add_argument("--letsencrypt-fake-cert")
    parser.add_argument("--log-level", default="info")
    parser.add_argument("--keep-certificate", action="append")
    parser.add_argument("--additional-domain", action="append")
    return parser.parse_args(args)


def main(args=sys.argv[1:]):
    """Parse command line, request new certs, clean up old ones."""
    config = parse_command_line(args)
    configure_logger(logger, config.log_level.upper())
    all_domains = get_all_domains(config)
    request_new_certs(config, all_domains)
    clean_up_certs(config, all_domains)


if __name__ == "__main__":
    main()
