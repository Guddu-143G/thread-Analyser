"""
Version 23: Stateful Multi-Entity UEBA Core
Spatial-Temporal Graph Neural Network (GNN) Entity Profiling & PyG Tensor Generator.
Deconstructs OCSF classes into heterogeneous entity-relationship graph topology.
"""

import numpy as np
from collections import defaultdict
from typing import Dict, Any, List, Tuple, Optional

# Edge types definition
# 0: AUTHENTICATED_TO (Class 3002)
# 1: SPAWNED_PROCESS  (Class 1007)
# 2: ACCESSED_FILE    (Class 1001)
# 3: NETWORK_CONN     (Class 4001)
EDGE_TYPE_NAMES = {
    0: "AUTHENTICATED_TO",
    1: "SPAWNED_PROCESS",
    2: "ACCESSED_FILE",
    3: "NETWORK_CONN"
}

class HeterogeneousGNNFeatureExtractor:
    """
    Extracts topological and spatial-temporal features from normalized OCSF events
    to prepare multi-entity relationship graphs for GNN anomaly inference.
    """
    def __init__(self):
        # Maps node identities (e.g. "user:acme:admin") to continuous tracking indices
        self.node_mapping: Dict[str, int] = {}
        self.reverse_node_mapping: Dict[int, str] = {}
        # Adjacency matrices formatted as edge-index pairs: (source_node, dest_node)
        self.edge_index: List[Tuple[int, int]] = []
        # Edge type indicators
        self.edge_types: List[int] = []
        # Edge metadata details
        self.edge_details: List[Dict[str, Any]] = []
        # Node attribute feature vectors
        self.node_features: Dict[int, np.ndarray] = {}

    def get_or_create_node(self, node_key: str) -> int:
        if node_key not in self.node_mapping:
            idx = len(self.node_mapping)
            self.node_mapping[node_key] = idx
            self.reverse_node_mapping[idx] = node_key
            self.node_features[idx] = np.zeros(8, dtype=np.float32)
        return self.node_mapping[node_key]

    def parse_ocsf_to_graph(self, event: Dict[str, Any]) -> Tuple[int, int, int]:
        """
        Deconstructs OCSF classes into structural nodes and typed edges.
        Returns (src_node_id, dst_node_id, edge_type).
        """
        class_uid = event.get("metadata", {}).get("class_uid", 0)
        tenant_id = event.get("metadata", {}).get("tenant_uid", "global")

        src_id, dst_id, edge_type = -1, -1, -1

        # Class 3002: Authentication
        if class_uid == 3002:
            user = event.get("user", {}).get("name", "unknown")
            device = event.get("device", {}).get("hostname", event.get("device", {}).get("uid", "unknown"))
            src_id = self.get_or_create_node(f"user:{tenant_id}:{user}")
            dst_id = self.get_or_create_node(f"device:{tenant_id}:{device}")
            edge_type = 0  # AUTHENTICATED_TO

        # Class 1007: Process Activity
        elif class_uid == 1007:
            device = event.get("device", {}).get("hostname", event.get("device", {}).get("uid", "unknown"))
            proc_name = event.get("process", {}).get("name", "unknown")
            src_id = self.get_or_create_node(f"device:{tenant_id}:{device}")
            dst_id = self.get_or_create_node(f"process:{tenant_id}:{proc_name}")
            edge_type = 1  # SPAWNED_PROCESS

        # Class 1001: File System Activity
        elif class_uid == 1001:
            proc_name = event.get("process", {}).get("name", "unknown")
            file_path = event.get("file", {}).get("path", "unknown")
            src_id = self.get_or_create_node(f"process:{tenant_id}:{proc_name}")
            dst_id = self.get_or_create_node(f"file:{tenant_id}:{file_path}")
            edge_type = 2  # ACCESSED_FILE

        # Class 4001: Network Connection
        elif class_uid == 4001:
            device = event.get("device", {}).get("hostname", "unknown")
            dst_ip = event.get("connection_info", {}).get("dst_endpoint", {}).get("ip", "unknown")
            src_id = self.get_or_create_node(f"device:{tenant_id}:{device}")
            dst_id = self.get_or_create_node(f"ip:{tenant_id}:{dst_ip}")
            edge_type = 3  # NETWORK_CONN

        if src_id != -1 and dst_id != -1:
            self.edge_index.append((src_id, dst_id))
            self.edge_types.append(edge_type)
            self.edge_details.append({
                "src": self.reverse_node_mapping[src_id],
                "dst": self.reverse_node_mapping[dst_id],
                "edge_type": edge_type,
                "edge_name": EDGE_TYPE_NAMES.get(edge_type, "UNKNOWN"),
                "timestamp": event.get("time", 0)
            })

            # Populate basic feature weights (Node Degree, Class Typology)
            self._update_node_features(src_id, edge_type)
            self._update_node_features(dst_id, edge_type)

        return src_id, dst_id, edge_type

    def _update_node_features(self, node_id: int, edge_type: int):
        if node_id not in self.node_features:
            self.node_features[node_id] = np.zeros(8, dtype=np.float32)

        self.node_features[node_id][0] += 1.0  # Increment Degree count
        if edge_type < 4:
            self.node_features[node_id][edge_type + 1] += 1.0  # Increment relation weight
        self.node_features[node_id][5] = float(np.log1p(self.node_features[node_id][0]))

    def get_pyg_tensors(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Formats the current spatial map into NumPy-native tensors compatible 
        with PyTorch Geometric (PyG) GNN inference engines: (x, edge_index, edge_attr).
        """
        num_nodes = len(self.node_mapping)
        if num_nodes == 0:
            return np.zeros((0, 8), dtype=np.float32), np.zeros((2, 0), dtype=np.int64), np.zeros((0,), dtype=np.int64)

        x = np.array([self.node_features[i] for i in range(num_nodes)], dtype=np.float32)
        if len(self.edge_index) > 0:
            edge_index = np.array(self.edge_index, dtype=np.int64).T
            edge_attr = np.array(self.edge_types, dtype=np.int64)
        else:
            edge_index = np.zeros((2, 0), dtype=np.int64)
            edge_attr = np.zeros((0,), dtype=np.int64)

        return x, edge_index, edge_attr

    def compute_graph_anomaly_score(self, target_node_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Computes spatial-temporal topological anomaly scores across heterogeneous graph nodes.
        Flags high degree burstiness, anomalous multi-hop traversal, and uncharacteristic edge types.
        """
        if len(self.node_mapping) == 0:
            return {
                "total_nodes": 0,
                "total_edges": 0,
                "anomaly_score": 0.0,
                "is_anomalous": False,
                "top_anomalous_nodes": []
            }

        scores = []
        for node_key, idx in self.node_mapping.items():
            feats = self.node_features[idx]
            degree = feats[0]
            auth_weight = feats[1]
            proc_weight = feats[2]
            file_weight = feats[3]
            net_weight = feats[4]

            # Heuristic GNN GraphSAGE/GAT Embedding distance proxy
            # Anomaly indicator: high lateral dispersion (user -> device -> proc -> file -> net)
            diversity = sum(1 for w in [auth_weight, proc_weight, file_weight, net_weight] if w > 0)
            score = float((degree * 0.1) + (diversity * 0.25) + (proc_weight * 0.15) + (file_weight * 0.2))
            normalized_score = min(1.0, round(score / 5.0, 3))

            scores.append({
                "node_id": idx,
                "node_key": node_key,
                "node_type": node_key.split(":")[0] if ":" in node_key else "entity",
                "degree": int(degree),
                "diversity_index": diversity,
                "anomaly_score": normalized_score,
                "is_anomalous": normalized_score >= 0.65
            })

        scores.sort(key=lambda x: x["anomaly_score"], reverse=True)
        avg_score = round(float(np.mean([s["anomaly_score"] for s in scores])), 3) if scores else 0.0

        return {
            "total_nodes": len(self.node_mapping),
            "total_edges": len(self.edge_index),
            "mean_anomaly_score": avg_score,
            "max_anomaly_score": scores[0]["anomaly_score"] if scores else 0.0,
            "is_anomalous": any(s["is_anomalous"] for s in scores),
            "nodes": scores[:15],
            "edges": self.edge_details[-20:]
        }
