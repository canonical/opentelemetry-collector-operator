# OpenTelemetry Collector Operator for Machines

[![CharmHub Badge](https://charmhub.io/opentelemetry-collector/badge.svg)](https://charmhub.io/opentelemetry-collector)
[![Release](https://github.com/canonical/opentelemetry-collector-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/opentelemetry-collector-operator/actions/workflows/release.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

This repository contains the source code for a Charmed Operator that drives [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector), a vendor-agnostic way to receive, process and export telemetry data, on machines (LXD, MAAS, etc).

## Usage
Assuming you have access to a bootstrapped Juju controller, you can:

```bash
$ juju deploy opentelemetry-collector
```
The `opentelemetry-collector` operator for machines is a subordinate charm.

It needs to be related to a principal charm. The principal charm needs to support relations through the `cos-agent` or `juju-info` interfaces.
For example, if you have the `ubuntu` principal, you can relate it to this charm:

```bash
$ juju integrate ubuntu opentelemetry-collector
```

Given that this charm is a subordinate, it scales up and down with its principal. As a result, if the `ubuntu` principal is scaled up to 2, a new machine is spun up and the `opentelemetry-collector` charm will be deployed in it and related to `ubuntu`.

## Snap

This charm uses the [Opentelemetry Collector snap](https://github.com/canonical/opentelemetry-collector-snap/).
When deployed, the charm will write a configuration file for the workload based on available integrations, configurations, etc and 
write it to the machine hosting the snap at `/etc/otelcol/config.d`.

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and the [contributing](https://github.com/canonical/opentelemetry-collector-operator/blob/main/CONTRIBUTING.md) doc for developer guidance.
