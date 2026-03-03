# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

# TODO: Update once we have moved to a lib
"""OpenTelemetry protocol (OTLP) Library.

## Overview

This document explains how to integrate with the Opentelemetry-collector charm
for the purpose of providing OTLP telemetry to Opentelemetry-collector. This document is the
authoritative reference on the structure of relation data that is
shared between Opentelemetry-collector charms and any other charm that intends to
provide OTLP telemetry for Opentelemetry-collector.
"""

import copy
import json
import logging
from lzma import LZMAError
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, OrderedDict, Sequence, Union

from cosl.juju_topology import JujuTopology
from cosl.rules import AlertRules, InvalidRulePathError, generic_alert_groups
from cosl.utils import LZMABase64
from ops import CharmBase
from ops.framework import Object
from pydantic import BaseModel, ConfigDict, ValidationError

DEFAULT_CONSUMER_RELATION_NAME = "send-otlp"
DEFAULT_PROVIDER_RELATION_NAME = "receive-otlp"
DEFAULT_LOKI_RULES_RELATIVE_PATH = "./src/loki_alert_rules"
DEFAULT_PROM_RULES_RELATIVE_PATH = "./src/prometheus_alert_rules"


logger = logging.getLogger(__name__)


class RulesModel(BaseModel):
    """A pydantic model for all rule formats."""

    model_config = ConfigDict(extra="forbid")

    logql: Dict[str, Any]
    promql: Dict[str, Any]


class OtlpEndpoint(BaseModel):
    """A pydantic model for a single OTLP endpoint."""

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["http", "grpc"]
    endpoint: str
    telemetries: Sequence[Literal["logs", "metrics", "traces"]]


class OtlpProviderAppData(BaseModel):
    """A pydantic model for the OTLP provider's unit databag."""

    model_config = ConfigDict(extra="forbid")

    endpoints: List[OtlpEndpoint]


class OtlpConsumerAppData(BaseModel):
    """A pydantic model for the OTLP consumer's unit databag.

    The rules are compressed when saved to databag to avoid hitting databag
    size limits for large deployments. An admin can decode the rules using the
    following command:
    ```bash
    <rules-from-show-unit> | base64 -d | xz -d | jq
    ```
    """

    model_config = ConfigDict(extra="forbid")

    rules: Union[RulesModel, str]
    metadata: OrderedDict[str, str]

    @staticmethod
    def decode_value(json_str: str) -> Any:
        """Decode relation data values using BaseModel validation."""
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            try:
                decompressed = LZMABase64.decompress(json_str)
                return RulesModel.model_validate(json.loads(decompressed))
            except (json.JSONDecodeError, ValidationError, LZMAError):
                return ""

    @staticmethod
    def encode_value(obj: Any) -> str:
        """Encode relation data values using BaseModel serialization."""
        try:
            RulesModel.model_validate(obj)
            return LZMABase64.compress(json.dumps(obj, sort_keys=True))
        except ValidationError:
            return json.dumps(obj, sort_keys=True)


class OtlpConsumer(Object):
    """A class for consuming OTLP endpoints.

    Args:
        charm: The charm instance.
        relation_name: The name of the relation to use.
        protocols: The protocols to filter for in the provider's OTLP
            endpoints.
        telemetries: The telemetries to filter for in the provider's OTLP
            endpoints.
        loki_rules_path: The path to Loki alerting and recording rules provided
            by this charm.
        prometheus_rules_path: The path to Prometheus alerting and recording
            rules provided by this charm.
    """

    # NOTE: The AlertRules class supports both alert and record rules.
    _rules_cls = AlertRules

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_CONSUMER_RELATION_NAME,
        protocols: Optional[Sequence[Literal["http", "grpc"]]] = None,
        telemetries: Optional[Sequence[Literal["logs", "metrics", "traces"]]] = None,
        *,
        loki_rules_path: str = DEFAULT_LOKI_RULES_RELATIVE_PATH,
        prometheus_rules_path: str = DEFAULT_PROM_RULES_RELATIVE_PATH,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._protocols = protocols if protocols is not None else []
        self._telemetries = telemetries if telemetries is not None else []
        self._topology = JujuTopology.from_charm(charm)
        charm_dir = self._charm.charm_dir
        self._loki_rules_path = self._validate_rules_path(loki_rules_path, charm_dir)
        self._prom_rules_path = self._validate_rules_path(prometheus_rules_path, charm_dir)

    def _validate_rules_path(self, rules_path: str, charm_dir: Path) -> str:
        """Validate the rules path and return an absolute path if valid.

        If the path is invalid, log a warning and return the original path.
        This method ensures that there is always a returned path, allowing
        later methods to error if these paths do not exist.
        """
        try:
            rules_path = self._rules_cls.resolve_dir_against_charm_path(
                rules_path, charm_dir=charm_dir
            )
        except InvalidRulePathError as e:
            logger.warning(
                "Invalid Prometheus alert rules folder at %s: %s", e.rules_absolute_path, e.message
            )
        return rules_path

    def _filter_endpoints(
        self, endpoints: List[Dict[str, Union[str, List[str]]]]
    ) -> List[OtlpEndpoint]:
        """Filter out unsupported OtlpEndpoints.

        For each endpoint:
            - If a telemetry type is not supported, then the endpoint is
              accepted, but the telemetry is ignored.
            - If there are no supported telemetries for this endpoint, the
              endpoint is ignored.
            - If the endpoint contains an unsupported protocol it is ignored.
        """
        valid_endpoints = []
        supported_telemetries = set(self._telemetries)
        for endpoint in endpoints:
            if filtered_telemetries := [
                t for t in endpoint.get("telemetries", []) if t in supported_telemetries
            ]:
                endpoint["telemetries"] = filtered_telemetries
            else:
                # If there are no supported telemetries for this endpoint, skip it entirely
                continue
            try:
                endpoint = OtlpEndpoint.model_validate(endpoint)
            except ValidationError:
                continue
            valid_endpoints.append(endpoint)

        return valid_endpoints

    def publish(self):
        """Triggers programmatically the update of the relation data.

        The rule files exist in separate directories, distinguished by format
        (logql|promql), each including alerting and recording rule types. The
        charm uses these paths as aggregation points for rules, acting as their
        source of truth. For each type of rule, the charm may aggregate rules
        from:
            - rules bundled in the charm's source code
            - any rules provided by related charms

        Generic, injected rules (not specific to any charm) are always
        published. Besides these generic rules, the inclusion of bundled rules
        and rules from related charms is the responsibility of the charm using
        the library. Including bundled rules and rules from related charms is
        achieved by copying these rules to the respective paths within the
        charm's filesystem and providing those paths to the OtlpConsumer
        constructor.
        """
        if not self._charm.unit.is_leader():
            # Only the leader unit can write to app data.
            return

        # Define the rule types
        loki_rules = self._rules_cls(query_type="logql", topology=self._topology)
        prom_rules = self._rules_cls(query_type="promql", topology=self._topology)

        # Add rules
        prom_rules.add(
            copy.deepcopy(generic_alert_groups.aggregator_rules),
            group_name_prefix=self._topology.identifier,
        )
        loki_rules.add_path(self._loki_rules_path, recursive=True)
        prom_rules.add_path(self._prom_rules_path, recursive=True)

        # Publish to databag
        databag = OtlpConsumerAppData.model_validate(
            {
                "rules": {"logql": loki_rules.as_dict(), "promql": prom_rules.as_dict()},
                "metadata": self._topology.as_dict(),
            }
        )
        for relation in self.model.relations[self._relation_name]:
            relation.save(databag, self._charm.app, encoder=OtlpConsumerAppData.encode_value)

    @property
    def endpoints(self) -> Dict[int, OtlpEndpoint]:
        """Return a mapping of relation ID to OTLP endpoint.

        For each remote's list of OtlpEndpoints, the consumer filters out
        unsupported endpoints and telemetries. If there are multiple supported
        endpoints, the consumer chooses the first available endpoint in the
        list. This allows providers to specify multiple endpoints with
        different protocols and/or telemetry types and the consumer can choose
        one based on its own capabilities. For example, a provider may specify
        both an HTTP and gRPC endpoint, and a consumer that only supports HTTP
        will choose the HTTP endpoint.
        """
        endpoint_map = {}
        for relation in self.model.relations[self._relation_name]:
            endpoints = json.loads(relation.data[relation.app].get("endpoints", "[]"))
            if not (endpoints := self._filter_endpoints(endpoints)):
                continue

            try:
                # Ensure that the databag is valid
                app_databag = OtlpProviderAppData(endpoints=endpoints)
            except ValidationError as e:
                logger.error(f"OTLP databag failed validation: {e}")
                continue

            # Choose the first valid endpoint in list
            if endpoint_choice := next(
                (e for e in app_databag.endpoints if e.protocol in self._protocols), None
            ):
                endpoint_map[relation.id] = endpoint_choice

        return endpoint_map


class OtlpProvider(Object):
    """A class for publishing all supported OTLP endpoints.

    Args:
        charm: The charm instance.
        relation_name: The name of the relation to use.
    """

    # NOTE: The AlertRules class supports both alert and record rules.
    _rules_cls = AlertRules

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_PROVIDER_RELATION_NAME,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._endpoints = []
        self._topology = JujuTopology.from_charm(charm)

    def add_endpoint(
        self,
        protocol: Literal["http", "grpc"],
        endpoint: str,
        telemetries: Sequence[Literal["logs", "metrics", "traces"]],
    ):
        """Add an OtlpEndpoint to the list of endpoints to publish.

        Call this method after endpoint-changing events e.g. TLS and ingress.
        """
        self._endpoints.append(
            OtlpEndpoint(protocol=protocol, endpoint=endpoint, telemetries=telemetries)
        )

    def publish(self) -> None:
        """Triggers programmatically the update of the relation data."""
        if not self._charm.unit.is_leader():
            # Only the leader unit can write to app data.
            return

        databag = OtlpProviderAppData.model_validate({"endpoints": self._endpoints})
        for relation in self.model.relations[self._relation_name]:
            relation.save(databag, self._charm.app)

    def rules(self, query_type: Literal["logql", "promql"]):
        """Fetch rules for all relations of the desired query and rule types.

        This method returns all rules of the desired query and rule types
        provided by related OTLP consumer charms. These rules may be used to
        generate a rules file for each relation since the returned list of
        groups are indexed by relation ID. This method ensures rules:
            - have Juju topology from the rule's labels injected into the expr.
            - are valid using CosTool.

        Returns:
            a mapping of relation ID to a dictionary of alert rule groups
            following the OfficialRuleFileFormat from cos-lib.
        """
        rules_obj = self._rules_cls(query_type, self._topology)

        rules_map = {}
        for relation in self.model.relations[self._relation_name]:
            consumer = relation.load(
                OtlpConsumerAppData, relation.app, decoder=OtlpConsumerAppData.decode_value
            )

            # get rules for the desired query type
            if not (rules := getattr(consumer.rules, rules_obj.query_type, None)):
                continue

            result = rules_obj.inject_and_validate_rules(rules, consumer.metadata)
            if result.errmsg:
                relation.data[self._charm.app]["event"] = json.dumps({"errors": result.errmsg})

            rules_map[result.identifier] = result.rules

        return rules_map
