output "app_name" {
  value = juju_application.opentelemetry_collector.name
}

output "endpoints" {
  value = {
    # Requires
    cloud_config                = "cloud-config",
    cos_agent                   = "cos-agent",
    grafana_dashboards_consumer = "grafana-dashboards-consumer",
    juju_info                   = "juju-info",
    metrics_endpoint            = "metrics-endpoint",
    receive_ca_cert             = "receive-ca-cert",
    receive_server_cert         = "receive-server-cert",
    send_charm_traces           = "send-charm-traces",
    send_loki_logs              = "send-loki-logs",
    send_otlp                   = "send-otlp",
    send_remote_write           = "send-remote-write",
    send_traces                 = "send-traces",

    # Provides
    grafana_dashboards_provider = "grafana-dashboards-provider",
    receive_loki_logs           = "receive-loki-logs",
    receive_traces              = "receive-traces",
  }
}
