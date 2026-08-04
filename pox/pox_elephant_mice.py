import json
import os
import time

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str

log = core.getLogger()

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


class ElephantMiceController:
    def __init__(self, model_path, metadata_path, poll_interval):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self.poll_interval = poll_interval
        self.mac_to_port = {}
        self.previous_stats = {}
        self.model = None
        self.feature_columns = DEFAULT_FEATURE_COLUMNS

        self._load_model()
        core.openflow.addListeners(self)
        Timer(self.poll_interval, self._request_flow_stats, recurring=True)
        log.info("Elephant/mice POX controller started with %.2fs polling", self.poll_interval)

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
            prediction = self._predict(features)
            self._log_prediction(event, stat, features, prediction)

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

    def _log_prediction(self, event, stat, features, prediction):
        match = stat.match
        log.info(
            "%s %s:%s -> %s:%s proto=%s packets=%d bytes=%d prediction=%s",
            dpid_to_str(event.dpid),
            match.nw_src,
            match.tp_src,
            match.nw_dst,
            match.tp_dst,
            match.nw_proto,
            features["total_packets"],
            features["total_bytes"],
            prediction,
        )


def launch(model_path="elephant_mice_model.pkl", metadata_path="model_metadata.json", poll_interval=1):
    poll_interval = float(poll_interval)
    ElephantMiceController(model_path, metadata_path, poll_interval)
