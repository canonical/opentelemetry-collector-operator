"""Helper module to manage snap Fstab files."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

_FsType = str
_MountOption = str
_MountOptions = List[_MountOption]


logger = logging.getLogger(__name__)


@dataclass
class _SnapFstabEntry:
    """Representation of an individual fstab entry for snap plugs."""

    source: str
    target: str
    fstype: Union[_FsType, None]
    options: _MountOptions
    dump: int
    fsck: int

    owner: str = field(init=False)
    endpoint_source: str = field(init=False)
    relative_target: str = field(init=False)

    def __post_init__(self):
        """Populate with calculated values at runtime."""
        self.owner = re.sub(
            r"^(.*?)?/snap/(?P<owner>([A-Za-z0-9_-])+)/.*$", r"\g<owner>", self.source
        )
        self.endpoint_source = re.sub(
            r"^(.*?)?/snap/([A-Za-z0-9_-])+/(?P<path>.*$)", r"\g<path>", self.source
        )
        self.relative_target = re.sub(
            r"^(.*?)?/snap/grafana-agent/\d+/shared-logs+(?P<path>/.*$)", r"\g<path>", self.target
        )


@dataclass
class SnapFstab:
    """Build a small representation/wrapper for snap fstab files."""

    fstab_file: Union[Path, str]
    entries: List[_SnapFstabEntry] = field(init=False)

    def __post_init__(self):
        """Populate with calculated values at runtime."""
        self.fstab_file = (
            self.fstab_file if isinstance(self.fstab_file, Path) else Path(self.fstab_file)
        )
        if not self.fstab_file.exists():
            self.entries = []
            return

        entries = []
        for line in self.fstab_file.read_text().split("\n"):
            if not line.strip():
                # skip whitespace-only lines
                continue
            raw_entry = line.split()
            fields = {
                "source": raw_entry[0],
                "target": raw_entry[1],
                "fstype": None if raw_entry[2] == "none" else raw_entry[2],
                "options": raw_entry[3].split(","),
                "dump": int(raw_entry[4]),
                "fsck": int(raw_entry[5]),
            }
            entry = _SnapFstabEntry(**fields)
            entries.append(entry)

        self.entries = entries

    def entry(self, owner: str, endpoint_name: Optional[str]) -> Optional[_SnapFstabEntry]:
        """Find and return a specific entry if it exists."""
        entries = [e for e in self.entries if e.owner == owner]

        if len(entries) > 1 and endpoint_name:
            # If there's more than one entry, the endpoint name may not directly map to
            # the source *or* path. charmed-kafka uses 'logs' as the plug name, and maps
            # .../common/logs to .../log inside Grafana Agent
            #
            # The only meaningful scenario in which this could happen (multiple fstab
            # entries with the same snap "owning" the originating path) is if a snap provides
            # multiple paths as part of the same plug.
            #
            # In this case, for a cheap comparison (rather than implementing some recursive
            # LCS just for this), convert all possible endpoint sources into a list of unique
            # characters, as well as the endpoint name, and build a sequence of entries with
            # a value that's the length of the intersection, the pick the first one i.e. the one
            # with the largest intersection.
            ordered_entries = sorted(
                entries,
                # descending order
                reverse=True,
                # size of the character-level similarity of the two strings
                key=lambda e: len(set(endpoint_name) & set(e.endpoint_source)),
            )
            return ordered_entries[0]

        if len(entries) > 1 or not entries:
            logger.debug(
                "Ambiguous or unknown mountpoint for snap %s at slot %s, not relabeling.",
                owner,
                endpoint_name,
            )
            return None

        return entries[0]
