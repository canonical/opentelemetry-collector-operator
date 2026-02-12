"""Miscellaneous ops-independent utilities."""

class InfoGauge:
    """Helper class for rendering info gauges."""

    def __init__(self, *, name: str, help_: str):
        self.name = name
        self.help_ = help_
        self.series: list[dict[str, str]] = []

    def add(self, labels: dict[str, str]):
        """Append another timeseries (specified by labels) under the same TYPE and HELP."""
        self.series.append(labels)

    def __str__(self):
        """Returns a /metrics-compatible multiline str."""
        help_ = f"# HELP {self.name} {self.help_}"
        type_ = f"# TYPE {self.name} gauge"

        metric_lines: list[str] = []

        for s in self.series:
            # Do not render curly braces if no labels present
            if s:
                labels = ",".join(f'{k}="{v}"' for k, v in sorted(s.items()))
                labels = f"{{{labels}}}"
            else:
                labels = ""

            metric_lines.append(f"{self.name}{labels} 1")

        return "\n".join([help_, type_, '\n'.join(metric_lines)]) if metric_lines else ""
