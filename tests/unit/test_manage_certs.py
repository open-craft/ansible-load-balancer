# -*- coding: utf-8 -*-
"""Unit tests for the manage_certs.py script."""

import argparse
import collections
import io
import logging
import unittest
from unittest import mock

import manage_certs


ALL_DOMAINS = collections.OrderedDict([
    ("main.server.domain", 0),
    ("some.domain.name", "be-corresponding-backend"),
    ("weird-whitespace.domain.name", "be-corresponding-backend"),
    ("uppercase.domain.name", "be-corresponding-backend"),
    ("different.backend.domain", "be-differenct-backend"),
    ("yet.another.backend.domain", "be-UPPERCASE-backend"),
])


class TestManageCerts(unittest.TestCase):
    """Unit tests for some of the certificate management functions."""

    def setUp(self):
        self.config = argparse.Namespace()

    def test_get_all_domains(self):
        """Test that get_all_domains() parses a backend map correctly."""
        self.config.haproxy_backend_map = mock.MagicMock()
        self.config.haproxy_backend_map.open.return_value.__enter__.return_value = io.StringIO(
            "# This is a comment.\n"
            "\n"
            "some.domain.name be-corresponding-backend\n"
            "  weird-whitespace.domain.name \t be-corresponding-backend  \n"
            # We want to make sure that upper-case domain names get converted to lower case...
            "UPPERCASE.domain.name be-corresponding-backend\n"
            "different.backend.domain be-differenct-backend\n"
            # ...but uppercase backend names will not be modified in any way.
            "yet.another.backend.domain be-UPPERCASE-backend\n"
        )
        self.config.additional_domain = ["main.server.domain"]
        all_domains = manage_certs.get_all_domains(self.config)
        self.assertEqual(all_domains, ALL_DOMAINS)

    @mock.patch("manage_certs.has_valid_dns_record")
    @mock.patch("manage_certs.has_valid_cert")
    def test_get_certless_domains(self, fake_has_valid_cert, fake_has_valid_dns_record):
        """Test the logic and logging in get_certless_domains()."""
        fake_has_valid_dns_record.side_effect = [
            True,   # main.server.domain
            True,   # some.domain.name
            False,  # weird-whitespace.domain.name
            True,   # uppercase.domain.name
            True,   # different.backend.domain
            False,  # yet.another.backend.domain
        ]
        fake_has_valid_cert.side_effect = [
            True,   # main.server.domain
            True,   # some.domain.name
            True,   # weird-whitespace.domain.name
            True,   # uppercase.domain.name
            False,  # different.backend.domain
            False,  # yet.another.backend.domain
        ]
        with self.assertLogs(manage_certs.logger, logging.DEBUG) as logs:
            certless_domains = manage_certs.get_certless_domains(self.config, ALL_DOMAINS)
        self.assertEqual(certless_domains, ["different.backend.domain"])
        self.assertEqual(logs.output, [
            'DEBUG:root:The DNS record for the domain main.server.domain points to this server.',
            'DEBUG:root:This server has a valid cert for the domain main.server.domain.',
            'DEBUG:root:The DNS record for the domain some.domain.name points to this server.',
            'DEBUG:root:This server has a valid cert for the domain some.domain.name.',
            'DEBUG:root:The DNS record for the domain weird-whitespace.domain.name does not point to this server.',
            'DEBUG:root:This server has a valid cert for the domain weird-whitespace.domain.name.',
            'DEBUG:root:The DNS record for the domain uppercase.domain.name points to this server.',
            'DEBUG:root:This server has a valid cert for the domain uppercase.domain.name.',
            'DEBUG:root:The DNS record for the domain different.backend.domain points to this server.',
            'DEBUG:root:This server does not have a valid cert for the domain different.backend.domain.',
            'DEBUG:root:The DNS record for the domain yet.another.backend.domain does not point to this server.',
            'DEBUG:root:This server does not have a valid cert for the domain yet.another.backend.domain.'
        ])

    @mock.patch("manage_certs.get_certless_domains")
    @mock.patch("manage_certs.request_cert")
    def test_request_new_certs(self, fake_request_cert, fake_get_certless_domains):
        """Test that new certs are requested for the correct domain groups."""
        fake_get_certless_domains.return_value = list(ALL_DOMAINS)
        manage_certs.request_new_certs(self.config, ALL_DOMAINS)
        self.assertCountEqual(fake_request_cert.call_args_list, [
            mock.call(self.config, ['main.server.domain']),
            mock.call(self.config, ['some.domain.name', 'weird-whitespace.domain.name', 'uppercase.domain.name']),
            mock.call(self.config, ['different.backend.domain']),
            mock.call(self.config, ['yet.another.backend.domain']),
        ])
