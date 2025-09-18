"""Profiling integration endpoint wrappers.

Install with:
> $ charmcraft fetch-lib charms.pyroscope_coordinator_k8s.v0.profiling

## Requirer usage

Update charmcraft.yaml to add a `profiling` requirer endpoint
```yaml
requires:
  profiling:
    interface: profiling
    optional: true
    description: Send profiles to a profiling backend (Pyroscope).
```

Then update your charm code:

```python
from charms.pyroscope_coordinator_k8s.v0.profiling import ProfilingEndpointRequirer, Endpoint
...
class MyCharm(ops.CharmBase):
        def __init__(self, ...):
            ...
            self._profiling = ProfilingEndpointRequirer(self.model.relations['profiling'])  # has to match the endpoint name declared in charmcraft.yaml

        @property
        def profiling_endpoints(self) -> List[Endpoint]:
            "The profiling backend endpoints we receive over the 'profiling' interface."
            return self._profiling.get_endpoints()

        def configure_profiling(self):
            "Configure your application to send profiles to the provided endpoint."
            for endpoint in self.profiling_endpoints:
                self.add_profiling_endpoint(url=endpoint.otlp_grpc, insecure=endpoint.insecure)
```

## Provider usage

Update charmcraft.yaml to add a `profiling` provider endpoint
```yaml
provides:
  profiling:
    interface: profiling
    optional: true
    description: Receive otel profiles.
```

Then update your charm code:

```python
from charms.pyroscope_coordinator_k8s.v0.profiling import ProfilingEndpointProvider
...
class MyCharm(ops.CharmBase):
        def __init__(self, ...):
            ...
            self._profiling = ProfilingEndpointProvider(self.model.relations['profiling'], self.application)

        def publish_profiling_endpoint(self):
            "Update all our `profiling` relations, advertising this unit's ingestion endpoint url."
            self._profiling.publish_endpoint(f"{socket.getfqdn()}:1239", insecure=True)
```
"""

import dataclasses
import logging
from typing import List

import ops
import pydantic

# The unique Charmhub library identifier, never change it
LIBID = "a04f470b17b64e9abcdb102f5458df55"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 5

DEFAULT_ENDPOINT_NAME = "profiling"

logger = logging.getLogger()


@dataclasses.dataclass
class Endpoint:
    """Profiling endpoint."""

    otlp_grpc: str
    """Ingestion endpoint for otlp_grpc profiling data."""
    insecure: bool = False
    """Whether the ingestion endpoint accepts/demands TLS-encrypted communications."""


class ProfilingAppDatabagModel(pydantic.BaseModel):
    """Application databag model for the profiling interface."""

    otlp_grpc_endpoint_url: str
    insecure: bool = False


class ProfilingEndpointProvider:
    """Wraps a profiling provider endpoint."""

    def __init__(self, relations: List[ops.Relation], app: ops.Application):
        self._relations = relations
        self._app = app

    def publish_endpoint(
        self,
        otlp_grpc_endpoint: str,
        insecure: bool = False,
    ):
        """Publish profiling ingestion endpoints to all relations."""
        for relation in self._relations:
            try:
                relation.save(
                    ProfilingAppDatabagModel(
                        otlp_grpc_endpoint_url=otlp_grpc_endpoint,
                        insecure=insecure,
                    ),
                    self._app,
                )
            except ops.ModelError:
                logger.debug(
                    "failed to validate app data; is the relation still being created?"
                )
                continue


class ProfilingEndpointRequirer:
    """Wraps a profiling requirer endpoint."""

    def __init__(self, relations: List[ops.Relation]):
        self._relations = relations

    def get_endpoints(self) -> List[Endpoint]:
        """Obtain the profiling endpoints from all relations."""
        out = []
        for relation in sorted(self._relations, key=lambda x: x.id):
            try:
                data = relation.load(ProfilingAppDatabagModel, relation.app)
            except ops.ModelError:
                logger.debug(
                    "failed to validate app data; is the relation still being created?"
                )
                continue
            except pydantic.ValidationError:
                logger.debug(
                    "failed to validate app data; is the relation still settling?"
                )
                continue
            out.append(
                Endpoint(
                    otlp_grpc=data.otlp_grpc_endpoint_url,
                    insecure=data.insecure,
                )
            )
        return out
