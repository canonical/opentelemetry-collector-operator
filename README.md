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

## Proxy configuration

The charm uses the Juju model's proxy settings by default. The model-level
[`juju-http-proxy`, `juju-https-proxy` and `juju-no-proxy` settings](https://documentation.ubuntu.com/juju/3.6/reference/juju-cli/list-of-juju-cli-commands/model-config/)
are applied to the snap's `http-proxy`, `https-proxy` and `no-proxy` options, which
the snap exports as the standard `HTTP(S)_PROXY`/`NO_PROXY` environment variables for
the collector process. For example:

```bash
$ juju model-config juju-https-proxy=http://squid.internal:3128
```

> **Breaking change:** with a model proxy set, the collector's HTTP and gRPC exports to
> endpoints inside the model (COS Loki, Prometheus/Mimir, Tempo, other collectors) are
> routed through the proxy, unless their addresses or CIDRs are listed in
> `juju-no-proxy`. To stop proxying a destination, add it to `juju-no-proxy`:
>
> ```bash
> $ juju model-config juju-no-proxy="10.0.0.0/8,.internal"
> ```

Local addresses (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0` and the machine's FQDN) are
always appended to `no-proxy`, so local scrapes and the collector's internal telemetry
bypass the proxy.

A change to the model's proxy settings restarts the collector, so the new settings
take effect immediately.

An invalid model proxy value is not applied: the unit blocks with a message naming the
offending setting, and the collector keeps the previously applied proxy settings. A value is
valid if it is a `scheme://[user[:pass]@]host[:port][/]` URL with an `http://`, `https://`,
`socks5://` or `socks5h://` scheme (case-insensitive) and a port in the 1-65535 range — the
same rules the snap applies. Credentials embedded in a rejected URL are masked in the unit's
status message and logs.

> **Note:** `socks5://` and `socks5h://` proxies only work for the collector's HTTP-based
> exporters; gRPC exporters require an HTTP(S) (CONNECT) proxy.

## Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and the [contributing](https://github.com/canonical/opentelemetry-collector-operator/blob/main/CONTRIBUTING.md) doc for developer guidance.
