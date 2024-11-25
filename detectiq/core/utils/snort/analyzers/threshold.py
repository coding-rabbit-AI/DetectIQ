from statistics import mean, median
from typing import Any, Dict, List

from .base import BaseAnalyzer


class ThresholdAnalyzer(BaseAnalyzer):
    """Analyzes traffic patterns to determine appropriate thresholds."""

    def analyze(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "rate_thresholds": self._calculate_rate_thresholds(analysis),
            "size_thresholds": self._calculate_size_thresholds(analysis),
            "frequency_thresholds": self._calculate_frequency_thresholds(analysis),
            "time_windows": self._calculate_time_windows(analysis),
        }

    def _calculate_rate_thresholds(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate rate-based thresholds."""
        flows = analysis.get("flows", [])
        packets_per_second = []
        bytes_per_second = []

        for flow in flows:
            if flow.get("duration", 0) > 0:
                pps = flow.get("packets", 0) / flow["duration"]
                bps = flow.get("bytes", 0) / flow["duration"]
                packets_per_second.append(pps)
                bytes_per_second.append(bps)

        return {
            "packets_per_second": self._calculate_threshold_levels(packets_per_second),
            "bytes_per_second": self._calculate_threshold_levels(bytes_per_second),
        }

    def _calculate_size_thresholds(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate size-based thresholds."""
        packet_sizes = []
        payload_sizes = []

        for content in analysis.get("content", {}).get("payload_patterns", []):
            size = content.get("size", 0)
            if size > 0:
                payload_sizes.append(size)

        return {
            "payload_size": self._calculate_threshold_levels(payload_sizes),
            "packet_size": self._calculate_threshold_levels(packet_sizes),
        }

    def _calculate_frequency_thresholds(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate frequency-based thresholds."""
        return {
            "connection_frequency": self._calculate_connection_thresholds(analysis),
            "request_frequency": self._calculate_request_thresholds(analysis),
        }

    def _calculate_time_windows(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate appropriate time windows for detection."""
        flows = analysis.get("flows", [])
        durations = [flow.get("duration", 0) for flow in flows if flow.get("duration", 0) > 0]

        if not durations:
            return self._get_default_time_windows()

        return {
            "min_window": max(1, round(min(durations))),
            "avg_window": max(1, round(mean(durations))),
            "med_window": max(1, round(median(durations))),
            "recommended": self._get_recommended_windows(durations),
        }

    @staticmethod
    def _calculate_threshold_levels(values: List[float]) -> Dict[str, float]:
        """Calculate threshold levels from a list of values."""
        if not values:
            return {"low": 0, "medium": 0, "high": 0}

        sorted_values = sorted(values)
        return {
            "low": sorted_values[int(len(sorted_values) * 0.50)],  # 50th percentile
            "medium": sorted_values[int(len(sorted_values) * 0.75)],  # 75th percentile
            "high": sorted_values[int(len(sorted_values) * 0.90)],  # 90th percentile
        }

    @staticmethod
    def _get_default_time_windows() -> Dict[str, Any]:
        """Get default time windows when no data is available."""
        return {
            "min_window": 1,
            "avg_window": 60,
            "med_window": 30,
            "recommended": {"fast": 1, "balanced": 30, "accurate": 300},
        }

    @staticmethod
    def _get_recommended_windows(durations: List[float]) -> Dict[str, int]:
        """Get recommended time windows based on traffic patterns."""
        return {
            "fast": max(1, round(min(durations))),
            "balanced": max(30, round(median(durations))),
            "accurate": max(300, round(mean(durations) * 2)),
        }

    def _calculate_connection_thresholds(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate connection frequency thresholds."""
        connections = analysis.get("connections", [])
        source_frequencies: Dict[str, int] = {}
        dest_frequencies: Dict[str, int] = {}
        port_frequencies: Dict[int, int] = {}

        # Calculate frequencies
        for conn in connections:
            src = conn.get("src", "")
            dst = conn.get("dst", "")
            dport = conn.get("dport")

            if src:
                source_frequencies[src] = source_frequencies.get(src, 0) + 1
            if dst:
                dest_frequencies[dst] = dest_frequencies.get(dst, 0) + 1
            if dport:
                port_frequencies[dport] = port_frequencies.get(dport, 0) + 1

        return {
            "source_ip": self._calculate_threshold_levels(list(source_frequencies.values())),
            "destination_ip": self._calculate_threshold_levels(list(dest_frequencies.values())),
            "destination_port": self._calculate_threshold_levels(list(port_frequencies.values())),
            "unique_sources": {"low": 5, "medium": 10, "high": 20},
            "unique_destinations": {"low": 3, "medium": 7, "high": 15},
        }

    def _calculate_request_thresholds(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate request frequency thresholds."""
        http_stats = self._extract_http_statistics(analysis)
        dns_stats = self._extract_dns_statistics(analysis)

        return {
            "http": {
                "requests_per_host": self._calculate_threshold_levels(http_stats["requests_per_host"]),
                "requests_per_path": self._calculate_threshold_levels(http_stats["requests_per_path"]),
                "requests_per_method": self._calculate_threshold_levels(http_stats["requests_per_method"]),
                "error_rates": {
                    "low": 0.05,  # 5% error rate
                    "medium": 0.15,  # 15% error rate
                    "high": 0.30,  # 30% error rate
                },
            },
            "dns": {
                "queries_per_domain": self._calculate_threshold_levels(dns_stats["queries_per_domain"]),
                "response_times": self._calculate_threshold_levels(dns_stats["response_times"]),
                "failure_rates": {
                    "low": 0.10,  # 10% failure rate
                    "medium": 0.25,  # 25% failure rate
                    "high": 0.40,  # 40% failure rate
                },
            },
        }

    def _extract_http_statistics(self, analysis: Dict[str, Any]) -> Dict[str, List[float]]:
        """Extract HTTP-specific statistics."""
        requests_per_host: Dict[str, int] = {}
        requests_per_path: Dict[str, int] = {}
        requests_per_method: Dict[str, int] = {}

        for conn in analysis.get("connections", []):
            if conn.get("protocol") == "HTTP":
                host = conn.get("http_host", "")
                path = conn.get("http_path", "")
                method = conn.get("http_method", "")

                if host:
                    requests_per_host[host] = requests_per_host.get(host, 0) + 1
                if path:
                    requests_per_path[path] = requests_per_path.get(path, 0) + 1
                if method:
                    requests_per_method[method] = requests_per_method.get(method, 0) + 1

        return {
            "requests_per_host": list(requests_per_host.values()),
            "requests_per_path": list(requests_per_path.values()),
            "requests_per_method": list(requests_per_method.values()),
        }

    def _extract_dns_statistics(self, analysis: Dict[str, Any]) -> Dict[str, List[float]]:
        """Extract DNS-specific statistics."""
        queries_per_domain: Dict[str, int] = {}
        response_times: List[float] = []

        for conn in analysis.get("connections", []):
            if conn.get("protocol") == "DNS":
                domain = conn.get("dns_query", "")
                response_time = conn.get("response_time")

                if domain:
                    queries_per_domain[domain] = queries_per_domain.get(domain, 0) + 1
                if response_time:
                    response_times.append(float(response_time))

        return {"queries_per_domain": list(queries_per_domain.values()), "response_times": response_times}

    def _calculate_adaptive_thresholds(self, values: List[float], sensitivity: float = 1.0) -> Dict[str, float]:
        """Calculate adaptive thresholds based on statistical properties."""
        if not values:
            return {"low": 0, "medium": 0, "high": 0}

        sorted_values = sorted(values)
        mean_val = mean(sorted_values)

        # Calculate standard deviation
        variance = sum((x - mean_val) ** 2 for x in values) / len(values)
        std_dev = variance**0.5

        return {
            "low": mean_val + (std_dev * sensitivity),
            "medium": mean_val + (std_dev * sensitivity * 2),
            "high": mean_val + (std_dev * sensitivity * 3),
        }

    def _calculate_baseline_thresholds(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate baseline thresholds for normal traffic patterns."""
        flows = analysis.get("flows", [])
        if not flows:
            return self._get_default_baseline_thresholds()

        # Calculate baseline metrics
        packets_per_flow = [flow.get("packets", 0) for flow in flows]
        bytes_per_flow = [flow.get("bytes", 0) for flow in flows]
        duration_per_flow = [flow.get("duration", 0) for flow in flows]

        return {
            "flow_packets": self._calculate_adaptive_thresholds(packets_per_flow),
            "flow_bytes": self._calculate_adaptive_thresholds(bytes_per_flow),
            "flow_duration": self._calculate_adaptive_thresholds(duration_per_flow),
            "update_interval": self._calculate_update_interval(duration_per_flow),
        }

    @staticmethod
    def _get_default_baseline_thresholds() -> Dict[str, Any]:
        """Get default baseline thresholds when no data is available."""
        return {
            "flow_packets": {"low": 100, "medium": 1000, "high": 10000},
            "flow_bytes": {"low": 10000, "medium": 100000, "high": 1000000},
            "flow_duration": {"low": 60, "medium": 300, "high": 3600},
            "update_interval": 3600,  # 1 hour default
        }

    @staticmethod
    def _calculate_update_interval(durations: List[float]) -> int:
        """Calculate appropriate interval for updating thresholds."""
        if not durations:
            return 3600  # Default 1 hour

        avg_duration = mean(durations)
        return max(300, min(3600, int(avg_duration * 2)))  # Between 5 minutes and 1 hour
