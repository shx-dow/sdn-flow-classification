import json
import os
import time

try:
    import flow_security_policy as policy
except ImportError:  # policy file not copied to ext/; degrade to log-only
    policy = None

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str

log = core.getLogger()

# Flow Security controller: dual classification (traffic x risk) with
# OpenFlow enforcement. Copy flow_security_policy.py next to this file.
DEFAULT_FEATURE_COLUMNS = [
    "protocol",
    "total_packets",
    "total_bytes",
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
]

DEFAULT_SECURITY_FEATURE_COLUMNS = [
    "syn_ratio",
    "rst_ratio",
    "icmp_ratio",
    "inter_arrival_std",
    "tcp_flag_entropy",
    "small_packet_ratio",
]

RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2}


class ElephantMiceController:
    def __init__(
        self,
        model_path,
        metadata_path,
        poll_interval,
        security_model_path="security_model.pkl",
        security_metadata_path="security_metadata.json",
        audit_path="flow_security_audit.jsonl",
    ):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self.poll_interval = poll_interval
        self.security_model_path = security_model_path
        self.security_metadata_path = security_metadata_path
        self.audit_path = audit_path
        self.mac_to_port = {}
        self.previous_stats = {}
        self.observations = {}
        self.model = None
        self.feature_columns = DEFAULT_FEATURE_COLUMNS
        self.security_model = None
        self.security_feature_columns = DEFAULT_SECURITY_FEATURE_COLUMNS

        self._load_model()
        self._load_security_model()
        core.openflow.addListeners(self)
        Timer(self.poll_interval, self._request_flow_stats, recurring=True)
        log.info("Flow Security POX controller started with %.2fs polling", self.poll_interval)

    def _load_model(self):
        try:
            import joblib

            self.model = joblib.load(self.model_path)
            if os.path.exists(self.metadata_path):
                with open(self.metadata_path) as metadata_file:
                    metadata = json.load(metadata_file)
                self.feature_columns = metadata.get("feature_columns", DEFAULT_FEATURE_COLUMNS)
            log.info("Loaded ML model from %s", self.model_path)
        except Exception as error:
            self.model = None
            log.warning("Could not load ML model: %s", error)
            log.warning("Controller will use threshold fallback predictions.")

    def _load_security_model(self):
        try:
            import joblib

            self.security_model = joblib.load(self.security_model_path)
            if os.path.exists(self.security_metadata_path):
                with open(self.security_metadata_path) as metadata_file:
                    metadata = json.load(metadata_file)
                self.security_feature_columns = metadata.get(
                    "feature_columns", DEFAULT_SECURITY_FEATURE_COLUMNS
                )
            log.info("Loaded security model from %s", self.security_model_path)
        except Exception as error:
            self.security_model = None
            log.warning("Could not load security model: %s", error)
            log.warning("Controller will use heuristic fallback risk predictions.")

    def _handle_ConnectionUp(self, event):
        log.info("Switch connected: %s", dpid_to_str(event.dpid))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        dpid = event.dpid
        in_port = event.port
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][packet.src] = in_port

        if packet.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][packet.dst]
        else:
            out_port = of.OFPP_FLOOD

        actions = [of.ofp_action_output(port=out_port)]

        if out_port != of.OFPP_FLOOD:
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, in_port)
            msg.idle_timeout = 20
            msg.hard_timeout = 0
            msg.actions = actions
            msg.data = event.ofp
            event.connection.send(msg)
        else:
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions = actions
            msg.in_port = in_port
            event.connection.send(msg)

        self._observe_packet(dpid, packet)

    def _obs_key(self, dpid, src, sport, dst, dport, proto):
        endpoint_a, endpoint_b = sorted(((src, sport), (dst, dport)))
        return (dpid, endpoint_a[0], endpoint_a[1], endpoint_b[0], endpoint_b[1], proto)

    def _observe_packet(self, dpid, packet):
        """Record per-flow flag/size observations for live security features.

        Never raises: observation is best-effort and must not disturb
        the learning-switch path.
        """
        if policy is None:
            return
        try:
            ip = packet.find("ipv4")
            if ip is None:
                return
            tcp = packet.find("tcp")
            udp = packet.find("udp")
            icmp = packet.find("icmp")
            if tcp is not None:
                sport, dport = tcp.srcport, tcp.dstport
                flags = getattr(tcp, "flags", None)
                flags = flags if isinstance(flags, int) else None
            elif udp is not None:
                sport, dport = udp.srcport, udp.dstport
                flags = None
            else:
                sport, dport = 0, 0
                flags = None
            size = len(packet.pack())
            key = self._obs_key(
                dpid, str(ip.srcip), int(sport), str(ip.dstip), int(dport), int(ip.protocol)
            )
            obs = self.observations.get(key)
            if obs is None:
                obs = policy.new_observation()
                self.observations[key] = obs
            policy.update_observation(
                obs,
                time.time(),
                tcp is not None,
                flags,
                icmp is not None or int(ip.protocol) == 1,
                size,
            )
        except Exception as error:
            log.warning("Observation failed: %s", error)

    def _request_flow_stats(self):
        for connection in core.openflow.connections:
            request = of.ofp_stats_request(body=of.ofp_flow_stats_request())
            connection.send(request)

    def _handle_FlowStatsReceived(self, event):
        now = time.time()
        for stat in event.stats:
            if self._skip_stat(stat):
                continue

            stat_key = self._stat_key(event.dpid, stat)
            previous = self.previous_stats.get(stat_key)
            self.previous_stats[stat_key] = {
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "seen_at": now,
            }

            if previous is None:
                continue

            total_packets = stat.packet_count - previous["packet_count"]
            total_bytes = stat.byte_count - previous["byte_count"]
            flow_duration = max(now - previous["seen_at"], 1e-9)

            if total_packets <= 0 or total_bytes <= 0:
                continue

            features = self._build_features(stat, total_packets, total_bytes, flow_duration)
            traffic = self._predict(features)
            if policy is None:
                self._log_prediction(event, stat, features, traffic, "Low", "forward")
                continue
            sec, obs_total = self._live_security_features(event.dpid, stat, features)
            risk = self._predict_risk(total_packets, features, sec, obs_total)
            action = self._decide(traffic, risk)
            self._enforce(event, stat, action)
            self._write_audit(event, stat, features, traffic, risk, action)
            self._log_prediction(event, stat, features, traffic, risk, action)

    def _skip_stat(self, stat):
        return stat.packet_count <= 0 or getattr(stat.match, "dl_type", None) != 0x800

    def _stat_key(self, dpid, stat):
        match = stat.match
        return (
            dpid,
            match.dl_type,
            match.nw_src,
            match.nw_dst,
            match.nw_proto,
            match.tp_src,
            match.tp_dst,
        )

    def _build_features(self, stat, total_packets, total_bytes, flow_duration):
        avg_packet_size = float(total_bytes) / float(total_packets)
        features = {
            "protocol": int(stat.match.nw_proto or 0),
            "total_packets": float(total_packets),
            "total_bytes": float(total_bytes),
            "flow_duration": float(flow_duration),
            "packet_rate": float(total_packets) / flow_duration,
            "byte_rate": float(total_bytes) / flow_duration,
            "avg_packet_size": avg_packet_size,
            "min_packet_size": avg_packet_size,
            "max_packet_size": avg_packet_size,
        }
        return features

    def _predict(self, features):
        if self.model is None:
            return self._threshold_prediction(features)

        row_values = [[features[column] for column in self.feature_columns]]
        try:
            import pandas as pd

            row = pd.DataFrame(row_values, columns=self.feature_columns)
        except Exception:
            row = row_values

        try:
            return self.model.predict(row)[0]
        except Exception as error:
            log.warning("Model prediction failed: %s", error)
            return self._threshold_prediction(features)

    def _threshold_prediction(self, features):
        if (
            features["total_bytes"] >= 1000000
            or features["flow_duration"] >= 10
            or features["total_packets"] >= 1000
        ):
            return "elephant"
        return "mice"

    def _live_security_features(self, dpid, stat, features):
        """Approximate security features from PacketIn observations.

        Returns (features, observed_total). Falls back to protocol-based
        defaults when no packets were observed for the flow.
        """
        match = stat.match
        key = self._obs_key(
            dpid,
            str(match.nw_src),
            int(match.tp_src or 0),
            str(match.nw_dst),
            int(match.tp_dst or 0),
            int(match.nw_proto or 0),
        )
        obs = self.observations.get(key)
        if obs is None or obs["total"] <= 0:
            avg = features["avg_packet_size"]
            small = 1.0 if avg < 200 else 0.0
            is_icmp = int(match.nw_proto or 0) == 1
            return (
                {
                    "syn_ratio": 0.0,
                    "rst_ratio": 0.0,
                    "icmp_ratio": 1.0 if is_icmp else 0.0,
                    "inter_arrival_std": 0.0,
                    "tcp_flag_entropy": 0.0,
                    "small_packet_ratio": small,
                },
                0,
            )
        return policy.live_security_features(obs), obs["total"]

    def _predict_risk(self, total_packets, features, sec, obs_total):
        """Conservative ensemble: max(model prediction, rate-aware heuristic).

        The heuristic sees FlowStats volume/rate, which the security model
        cannot (its 6 features are flag/size/timing only). Severity order:
        Low < Medium < High.
        """
        heuristic = policy.risk_heuristic(
            max(obs_total, int(total_packets)), float(features["packet_rate"]), sec
        )
        if self.security_model is None:
            return heuristic
        row_values = [[sec[column] for column in self.security_feature_columns]]
        try:
            import pandas as pd

            row = pd.DataFrame(row_values, columns=self.security_feature_columns)
        except Exception:
            row = row_values
        try:
            model_risk = self.security_model.predict(row)[0]
        except Exception as error:
            log.warning("Security prediction failed: %s", error)
            return heuristic
        if model_risk not in RISK_ORDER or heuristic not in RISK_ORDER:
            return heuristic
        if RISK_ORDER[model_risk] >= RISK_ORDER[heuristic]:
            return model_risk
        return heuristic

    def _decide(self, traffic, risk):
        try:
            return policy.decide(traffic, risk)
        except Exception as error:
            log.warning("Decision failed (%s); monitoring flow.", error)
            return "monitor"

    def _enforce(self, event, stat, action):
        """Translate the action into OpenFlow rules (best-effort).

        forward/monitor/reroute keep the learned path and differ only in
        the audit trail (reroute is a policy hook for multi-switch paths).
        rate_limit deletes the entry to force slow-path re-forwarding
        (OF 1.0 has no meters); block installs a drop rule.
        """
        try:
            if action == "block":
                msg = of.ofp_flow_mod()
                msg.match = stat.match
                msg.priority = 100
                msg.idle_timeout = 0
                msg.hard_timeout = 60
                msg.actions = []
                event.connection.send(msg)
            elif action == "rate_limit":
                msg = of.ofp_flow_mod()
                msg.command = of.OFPFC_DELETE
                msg.match = stat.match
                event.connection.send(msg)
        except Exception as error:
            log.warning("Enforcement failed for action %s: %s", action, error)

    def _write_audit(self, event, stat, features, traffic, risk, action):
        match = stat.match
        record = {
            "ts": time.time(),
            "dpid": dpid_to_str(event.dpid),
            "nw_src": str(match.nw_src),
            "tp_src": int(match.tp_src or 0),
            "nw_dst": str(match.nw_dst),
            "tp_dst": int(match.tp_dst or 0),
            "nw_proto": int(match.nw_proto or 0),
            "packets": features["total_packets"],
            "bytes": features["total_bytes"],
            "traffic": traffic,
            "risk": risk,
            "action": action,
        }
        try:
            with open(self.audit_path, "a") as audit_file:
                audit_file.write(json.dumps(record) + "\n")
        except Exception as error:
            log.warning("Audit write failed: %s", error)

    def _log_prediction(self, event, stat, features, traffic, risk, action):
        match = stat.match
        log.info(
            "%s %s:%s -> %s:%s proto=%s packets=%d bytes=%d traffic=%s risk=%s action=%s",
            dpid_to_str(event.dpid),
            match.nw_src,
            match.tp_src,
            match.nw_dst,
            match.tp_dst,
            match.nw_proto,
            features["total_packets"],
            features["total_bytes"],
            traffic,
            risk,
            action,
        )


def launch(
    model_path="elephant_mice_model.pkl",
    metadata_path="model_metadata.json",
    poll_interval=1,
    security_model_path="security_model.pkl",
    security_metadata_path="security_metadata.json",
    audit_path="flow_security_audit.jsonl",
):
    poll_interval = float(poll_interval)
    ElephantMiceController(
        model_path,
        metadata_path,
        poll_interval,
        security_model_path,
        security_metadata_path,
        audit_path,
    )
