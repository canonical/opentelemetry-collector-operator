# OpenTelemetry Collector Operator for Machines

[![CharmHub Badge](https://charmhub.io/opentelemetry-collector/badge.svg)](https://charmhub.io/opentelemetry-collector)
[![Release](https://github.com/canonical/opentelemetry-collector-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/opentelemetry-collector-k8s-operator/actions/workflows/release.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

This repository contains the source code for a Charmed Operator that drives [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector), a vendor-agnostic way to receive, process and export telemetry data, on machines (LXD, MAAS, etc).

## Usage

Assuming you have access to a bootstrapped Juju controller, you can:

```bash
$ juju deploy opentelemetry-collector
```

## Snap

This charm uses the [Opentelemetry Collector snap](https://github.com/canonical/opentelemetry-collector-snap/).

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and the [contributing](https://github.com/canonical/opentelemetry-collector-k8s-operator/blob/main/CONTRIBUTING.md) doc for developer guidance.
