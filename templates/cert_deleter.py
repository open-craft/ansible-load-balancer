#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Certificate removal for haproxy load balancing server.

Certificates are marked for removal by the manage_certs.py script.
Those marks come in the form of file indicators, which this script
searches for and subsequently uses to help delete those files.

# TODO: There's no functionality yet to unmark a cert for deletion,
#       in case, for example, the backend comes back online before
#       the removal date. This should be taken care of in the
#       manage_certs.py script.
"""

import datetime
import os
import pathlib
import sys
import shutil
import time


if __name__ == "__main__":
    assert len(sys.argv) == 2, "Expects only a directory input to search for " \
                               "domain names marked for cert deletion."

    deletion_dir = sys.argv[1]
    for domain in pathlib.Path(deletion_dir).iterdir():
        # TODO: Make frequency of deletion configurable; it's 15 days by default right now.
        # TODO: The paths also aren't configurable; they should come from the ansible variables or CLI.
        if os.path.getctime(domain.as_posix()) < (datetime.datetime.now() - datetime.timedelta(days=15)).timestamp():
            pathlib.Path("/etc/haproxy/certs", domain.name + ".pem").unlink()
            pathlib.Path("/etc/letsencrypt/renewal", domain.name + ".conf").unlink()
            shutil.rmtree("/etc/letsencrypt/live/" + domain.name, ignore_errors=True)
            shutil.rmtree("/etc/letsencrypt/archive/" + domain.name, ignore_errors=True)
            domain.unlink()
