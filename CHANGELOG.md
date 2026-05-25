## Breaking Changes

- fix!: Otelcol self-mon logs syslog explosion (#138)

## Features

- feat: Drop limit: 1 in send-traces (#235)
- feat(terraform): add channel validation and split outputs (#257)
- feat: Use the provider's insecure flag in OTLP databag (#250)
- feat: Forward OTLP rules from databag, not aggregation directory (#234)
- feat: New usage of otlp lib with the Rules interface (#227)
- feat: support for sending traces (#230)
- feat: send otlp endpoint in terraform (#189)
- feat: send-otlp relation for forwarding OTLP metrics (#175)
- feat: add configurable port overrides (#194)
- feat: node exporter grafana dashboard (#185)
- feat: nopexporter in production with debugexporter option (#142)
- feat: change default track to 'dev' in release workflow

## Fixes

- fix: snaps not updated on charm refresh due to wrong hook name (#258)
- fix: No metric normalization in prometheus components (#247)
- fix: Escape `$` in Prometheus scrape configs (#242)
- fix: update descriptions of tracing relations in charmcraft.yaml (#239)
- fix: remove overview dashboard uid and update title (#223)
- fix: overview dashboard dropdowns (#220)
- fix: `cos_agent` regression with fetch-lib (#191)
- fix: add dynamic port allocation for node-exporter (#181)
- fix: add instance label to log slots (#180)
- fix: observe reconcile action event as condition to refresh certs (#165)
- fix: guard ca cert refresh on specific hooks (#152)
- fix: use machine id for receiver (#162)
- fix: typos in readme (#159)
- fix: save `ca_file` to disk and reconfigure scrape jobs accordingly (#118)
- fix: TLS certificates integration (#132)

## Others

- add charms.just blueprint
- changelog implementation attempt
- chore(ci): bump reusable workflows to v2 (#263)
- fix remote build by adding cryptography build dependencies (#259)
- docs: improve charmcraft.yaml description field (#253)
- s390x support (#199)
- chore: update charm libraries (#240)
- refactor: Remove asyncio from itests (#237)
- feature: Integration with otelcol-integrator charm (#225)
- fix icon.svg size (#218)
- fix internal telemetry port assignation (#214)
- update node-exporter (#206)
- chore: update charm libraries (#182)
- chore: update charm libraries (#177)
- chore: update charm libraries (#173)
- chore: update charm libraries (#169)
- Add Juju controller/client versions prompt
- Add observability issue template (#143)
- Add checklist to PR template (#157)
- chore: update charm libraries (#145)
- Write current hash to file if changed (#147)
- chore: update charm libraries (#144)
- chore: update charm libraries (#141)
- chore: README (#137)
- chore: implement new prometheus remote write requirements (#130)
- chore: update charm libraries (#119)

