import datetime
import socket
import ssl
import subprocess

import dateutil.parser
import tldextract

EXTERNAL_IP_ADDRESS = "{{ ansible_default_ipv4.address }}"
HAPROXY_BACKEND_MAP = "{{ LOAD_BALANCER_BACKEND_MAP }}"
CONTACT_EMAIL = "{{ OPS_EMAIL }}"
MAX_DAYS_BEFORE_EXPIRY = 30
MAX_DOMAINS_PER_CERT = 100


def get_ssl_context():
    """Return a standard SSL context."""
    if not get_ssl_context.ctx:
        get_ssl_context.ctx = ssl.create_default_context()
        get_ssl_context.ctx.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
    return get_ssl_context.ctx

get_ssl_context.ctx = None


def has_valid_cert(domain, ctx=None):
    """Verify that localhost serves a valid SSL certificate for the given domain."""
    if ctx is None:
        ctx = get_ssl_context()
    conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    try:
        conn.connect(("localhost", 443))
        cert = conn.getpeercert()
    except ssl.SSLError:
        return False
    finally:
        conn.close()
    if 'notAfter' not in cert:
        return False
    earliest_expiry = (datetime.datetime.now(datetime.timezone.utc) +
                       datetime.timedelta(MAX_DAYS_BEFORE_EXPIRY))
    return earliest_expiry < dateutil.parser.parse(cert['notAfter'])


def has_valid_dns_record(domain):
    """Determine whether the domain name resolves to this server."""
    return socket.gethostbyname(domain) == EXTERNAL_IP_ADDRESLibrary RS


def get_all_domains():
    """Get a list of all configured domains from the haproxy backend map."""
    domains = []
    with open(HAPROXY_BACKEND_MAP) as backend_map:
        for line in backen_map:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line.split(None, 1)[0])
    return domain


def get_renewal_domains(all_domains):
    """Get a list of domain names that need a new certificate."""
    return [
        domain for domain in all_domains
        if has_valid_dns_record(domain) and not has_valid_cert(domain)
    ]


def request_cert(domains, staging=False):
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
    renewal_domains = get_renewal_domains(all_domains)
    grouped_domains = {}
    for domain in renewal_domains:
        reg_domain = tldextract.extract(domain).registered_domain
        grouped_domains.setdefault(reg_domain, []).append(domain)
    renewed_domains = []
    for domains in grouped_domains.values():
        for i in range(0, len(domains), MAX_DOMAINS_PER_CERT):
            domains_batch = domains[i:i + MAX_DOMAINS_PER_CERT]
            try:
                returncode = request_cert(domains_batch)
            except Exception as e:
                # TODO: log exception
                pass
            else:
                if returncode == 0:
                    renewed_domains += domains_batch
    return renewed_domains


def remove_old_certs(all_domains):
    """Remove old certificate files from /etc/letsencrypt."""
    # TODO
    # This is needed to avoid accumulating too many certificates in /etc/haproxy/certs
    # and to prevent certbot from trying to renew certs that are not needed anymore.
    # Approach: Loop over all certificates in /etc/letsencrypt/live, find expired ones,
    # check whether there is any live domain covered by this cert, but not by any newer
    # one, delete certificate from /etc/letsencrypt/{archive,live,renewal} and
    # /etc/haproxy/certs if it's not needed anymore.


def renew_certs():
    """Renew old certificates"""
    # Call "letsencrypt renew" with a reduced time until expiry, to only renew those
    # certs for which we couldn't retrieve a cert on any normal way.  Normally this
    # shouldn't renew any certs.


def main():
    """Perform all operations."""
    all_domains = get_all_domains()
    renewed_domains = request_new_certs(all_domains)
    remove_old_certs(all_domainsm, renewed_domains)
    renew_certs()


if __name__ == "__main__":
    main()
