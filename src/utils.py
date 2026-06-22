# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utils module."""

import logging
import os
from pathlib import Path
from typing import List

from charmlibs.pathops import LocalPath

from config_builder import sha256

logger = logging.getLogger(__name__)


def _get_cgroup_memory_max_path() -> Path:
    # TODO: this should accept a snap name or PID as an arg
    return Path("/sys/fs/cgroup/memory.max")


def total_memory_mib() -> int:
    """Return the total memory available to this process in MiB.

    Reads the cgroup memory limit, which reflects container/LXD limits.
    Falls back to physical RAM when the cgroup file is absent or reads "max"
    (meaning no limit is set).

    We need this function until this issue is closed:
        - https://github.com/canonical/opentelemetry-collector-operator/issues/256
    """
    try:
        raw = _get_cgroup_memory_max_path().read_text().strip()
        if raw != "max":
            return int(raw) // (1024 * 1024)
    except (OSError, ValueError):
        pass
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)


def hash_ca_cert_dir(folder: str) -> str:
    """Hash the CA certificate files materialized on disk.

    The otelcol snap only reloads the trusted CAs when its process is restarted; a
    running snap keeps its trust store cached. The restart must therefore be driven
    by what ``update-ca-certificates`` actually folds into the system bundle, i.e. the
    ``*.crt`` files written under ``RECV_CA_CERT_FOLDER_PATH`` (both the
    ``receive-ca-cert`` CAs and the ``receive-server-cert`` ``cos-ca.crt``).

    Hashing the relation data instead is unreliable: the ``certificate_transfer`` v1
    handshake can deliver certs across multiple hooks, so the relation-derived hash
    can settle (and the restart fire against the old bundle) on a hook that runs
    *before* the one that actually refreshes the system trust store. Hashing the
    on-disk files keeps the restart trigger aligned with the bytes the snap will load.

    Args:
        folder: Directory holding the CA certificate files (``*.crt``).

    Returns:
        A stable hash of the directory's certificate files, by name and content.
    """
    path = LocalPath(folder)
    if not path.exists():
        return sha256("")
    parts: List[str] = []
    for cert in sorted(path.glob("*.crt"), key=lambda p: p.name):
        parts.append(cert.name)
        parts.append(cert.read_text())
    return sha256("".join(parts))
