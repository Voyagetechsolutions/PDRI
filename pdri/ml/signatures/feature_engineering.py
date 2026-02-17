"""
Feature Engineering Module
==========================

Extract ML features from the risk graph for model training and prediction.

Features are extracted from:
    - Node attributes (sensitivity, volatility, exposure)
    - Edge relationships (vendor connections, data flows)
    - Temporal patterns (risk score history, access patterns)
    - Graph topology (centrality, clustering)

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


class FeatureCategory(Enum):
    """Categories of ML features."""
    NODE_STATIC = "node_static"      # Static node properties
    NODE_TEMPORAL = "node_temporal"   # Time-series node features
    EDGE_STATIC = "edge_static"       # Static relationship features
    EDGE_TEMPORAL = "edge_temporal"   # Time-series relationship features
    GRAPH_TOPOLOGY = "graph_topology" # Structural graph features
    BEHAVIORAL = "behavioral"          # Usage pattern features


@dataclass
class FeatureVector:
    """A vector of features for ML models."""
    node_id: str
    timestamp: datetime
    features: Dict[str, float]
    feature_names: List[str]
    category_breakdown: Dict[FeatureCategory, List[str]] = field(default_factory=dict)
    
    def to_numpy(self) -> np.ndarray:
        """Convert to numpy array."""
        return np.array([self.features[name] for name in self.feature_names])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "node_id": self.node_id,
            "timestamp": self.timestamp.isoformat(),
            "features": self.features,
            "feature_names": self.feature_names,
        }


@dataclass
class FeatureSchema:
    """Schema defining expected features."""
    name: str
    category: FeatureCategory
    dtype: str  # "float", "int", "bool"
    description: str
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    default_value: float = 0.0


class FeatureEngineer:
    """
    Extract and engineer features from the risk graph.
    
    This class transforms raw graph data into ML-ready feature vectors
    that capture:
    - Node-level risk indicators
    - Relationship patterns
    - Temporal trends
    - Graph topology characteristics
    
    Example:
        engineer = FeatureEngineer(graph_engine)
        features = await engineer.extract_features("node-123")
        vector = features.to_numpy()
    """
    
    # Feature definitions
    FEATURE_SCHEMAS: List[FeatureSchema] = [
        # Node static features
        FeatureSchema("sensitivity_score", FeatureCategory.NODE_STATIC, "float",
                     "Data sensitivity level (0-1)", 0.0, 1.0),
        FeatureSchema("volatility_score", FeatureCategory.NODE_STATIC, "float",
                     "Configuration volatility (0-1)", 0.0, 1.0),
        FeatureSchema("exposure_score", FeatureCategory.NODE_STATIC, "float",
                     "External exposure level (0-1)", 0.0, 1.0),
        FeatureSchema("current_risk_score", FeatureCategory.NODE_STATIC, "float",
                     "Current calculated risk score (0-100)", 0.0, 100.0),
        FeatureSchema("is_ai_tool", FeatureCategory.NODE_STATIC, "bool",
                     "Whether node is an AI tool", 0.0, 1.0),
        FeatureSchema("is_external_service", FeatureCategory.NODE_STATIC, "bool",
                     "Whether node is external/third-party", 0.0, 1.0),
        FeatureSchema("is_data_store", FeatureCategory.NODE_STATIC, "bool",
                     "Whether node is a data store", 0.0, 1.0),
        
        # Node temporal features
        FeatureSchema("risk_score_7d_avg", FeatureCategory.NODE_TEMPORAL, "float",
                     "7-day rolling average risk score", 0.0, 100.0),
        FeatureSchema("risk_score_7d_std", FeatureCategory.NODE_TEMPORAL, "float",
                     "7-day risk score standard deviation", 0.0, 50.0),
        FeatureSchema("risk_score_trend", FeatureCategory.NODE_TEMPORAL, "float",
                     "Risk score trend (-1 to 1)", -1.0, 1.0),
        FeatureSchema("days_since_last_change", FeatureCategory.NODE_TEMPORAL, "float",
                     "Days since last configuration change", 0.0, 365.0),
        FeatureSchema("changes_last_30d", FeatureCategory.NODE_TEMPORAL, "int",
                     "Number of changes in last 30 days", 0.0, 1000.0),
        
        # Edge features
        FeatureSchema("inbound_connection_count", FeatureCategory.EDGE_STATIC, "int",
                     "Number of inbound connections", 0.0, 1000.0),
        FeatureSchema("outbound_connection_count", FeatureCategory.EDGE_STATIC, "int",
                     "Number of outbound connections", 0.0, 1000.0),
        FeatureSchema("ai_tool_connection_count", FeatureCategory.EDGE_STATIC, "int",
                     "Number of connections to AI tools", 0.0, 100.0),
        FeatureSchema("external_connection_count", FeatureCategory.EDGE_STATIC, "int",
                     "Number of external connections", 0.0, 100.0),
        FeatureSchema("sensitive_data_flow_count", FeatureCategory.EDGE_STATIC, "int",
                     "Number of sensitive data flows", 0.0, 100.0),
        
        # Graph topology features
        FeatureSchema("degree_centrality", FeatureCategory.GRAPH_TOPOLOGY, "float",
                     "Node degree centrality", 0.0, 1.0),
        FeatureSchema("betweenness_centrality", FeatureCategory.GRAPH_TOPOLOGY, "float",
                     "Node betweenness centrality", 0.0, 1.0),
        FeatureSchema("clustering_coefficient", FeatureCategory.GRAPH_TOPOLOGY, "float",
                     "Local clustering coefficient", 0.0, 1.0),
        FeatureSchema("shortest_path_to_external", FeatureCategory.GRAPH_TOPOLOGY, "float",
                     "Shortest path length to external system", 0.0, 100.0),
        FeatureSchema("exposure_path_count", FeatureCategory.GRAPH_TOPOLOGY, "int",
                     "Number of paths to external exposure", 0.0, 1000.0),
        
        # Behavioral features
        FeatureSchema("access_frequency_24h", FeatureCategory.BEHAVIORAL, "float",
                     "Access frequency in last 24 hours", 0.0, 10000.0),
        FeatureSchema("unique_accessor_count", FeatureCategory.BEHAVIORAL, "int",
                     "Unique entities accessing this node", 0.0, 1000.0),
        FeatureSchema("anomalous_access_count", FeatureCategory.BEHAVIORAL, "int",
                     "Anomalous access events detected", 0.0, 100.0),
    ]
    
    def __init__(self, graph_engine: Any, score_history: Optional[Dict[str, List[Tuple[datetime, float]]]] = None):
        """
        Initialize feature engineer.
        
        Args:
            graph_engine: Neo4j graph engine instance
            score_history: Optional historical score data (node_id -> [(timestamp, score), ...])
        """
        self.graph_engine = graph_engine
        self.score_history = score_history or {}
        self._feature_names = [schema.name for schema in self.FEATURE_SCHEMAS]
        self._schema_map = {schema.name: schema for schema in self.FEATURE_SCHEMAS}
    
    @property
    def feature_names(self) -> List[str]:
        """Get ordered list of feature names."""
        return self._feature_names.copy()
    
    @property
    def feature_count(self) -> int:
        """Get total number of features."""
        return len(self._feature_names)
    
    async def extract_features(
        self,
        node_id: str,
        timestamp: Optional[datetime] = None
    ) -> FeatureVector:
        """
        Extract all features for a node.
        
        Args:
            node_id: ID of the node to extract features for
            timestamp: Point in time for feature extraction (defaults to now)
        
        Returns:
            FeatureVector with all computed features
        """
        timestamp = timestamp or datetime.utcnow()
        
        # Get node data from graph
        node_data = await self._get_node_data(node_id)
        
        # Extract features by category
        features = {}
        category_breakdown = {}
        
        # Node static features
        static_features = await self._extract_node_static_features(node_id, node_data)
        features.update(static_features)
        category_breakdown[FeatureCategory.NODE_STATIC] = list(static_features.keys())
        
        # Node temporal features
        temporal_features = await self._extract_node_temporal_features(node_id, timestamp)
        features.update(temporal_features)
        category_breakdown[FeatureCategory.NODE_TEMPORAL] = list(temporal_features.keys())
        
        # Edge features
        edge_features = await self._extract_edge_features(node_id)
        features.update(edge_features)
        category_breakdown[FeatureCategory.EDGE_STATIC] = list(edge_features.keys())
        
        # Topology features
        topology_features = await self._extract_topology_features(node_id)
        features.update(topology_features)
        category_breakdown[FeatureCategory.GRAPH_TOPOLOGY] = list(topology_features.keys())
        
        # Behavioral features
        behavioral_features = await self._extract_behavioral_features(node_id, timestamp)
        features.update(behavioral_features)
        category_breakdown[FeatureCategory.BEHAVIORAL] = list(behavioral_features.keys())
        
        # Ensure all features are present with defaults
        for schema in self.FEATURE_SCHEMAS:
            if schema.name not in features:
                features[schema.name] = schema.default_value
        
        return FeatureVector(
            node_id=node_id,
            timestamp=timestamp,
            features=features,
            feature_names=self._feature_names,
            category_breakdown=category_breakdown,
        )
    
    async def extract_batch_features(
        self,
        node_ids: List[str],
        timestamp: Optional[datetime] = None
    ) -> List[FeatureVector]:
        """
        Extract features for multiple nodes.
        
        Args:
            node_ids: List of node IDs
            timestamp: Point in time for extraction
        
        Returns:
            List of FeatureVectors
        """
        # In production, this would be optimized for batch queries
        results = []
        for node_id in node_ids:
            try:
                vector = await self.extract_features(node_id, timestamp)
                results.append(vector)
            except Exception as e:
                # Log error and continue with other nodes
                print(f"Error extracting features for {node_id}: {e}")
        return results
    
    async def _get_node_data(self, node_id: str) -> Dict[str, Any]:
        """Get node data from graph."""
        # Query graph for node
        if hasattr(self.graph_engine, 'get_node'):
            node = await self.graph_engine.get_node(node_id)
            if node:
                return node.__dict__ if hasattr(node, '__dict__') else dict(node)
        return {}
    
    async def _extract_node_static_features(
        self,
        node_id: str,
        node_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """Extract static node features."""
        features = {}
        
        # Direct attribute mappings
        features["sensitivity_score"] = float(node_data.get("sensitivity_level", 0.5))
        features["volatility_score"] = float(node_data.get("volatility", 0.3))
        features["exposure_score"] = float(node_data.get("exposure", 0.3))
        features["current_risk_score"] = float(node_data.get("risk_score", 50.0))
        
        # Node type flags
        node_type = node_data.get("node_type", "").lower()
        features["is_ai_tool"] = 1.0 if "ai" in node_type else 0.0
        features["is_external_service"] = 1.0 if node_data.get("is_external", False) else 0.0
        features["is_data_store"] = 1.0 if "data" in node_type or "store" in node_type else 0.0
        
        return features
    
    async def _extract_node_temporal_features(
        self,
        node_id: str,
        timestamp: datetime
    ) -> Dict[str, float]:
        """Extract temporal features from score history."""
        features = {}
        
        # Get score history for this node
        history = self.score_history.get(node_id, [])
        
        if history:
            # Filter to last 7 days
            week_ago = timestamp - timedelta(days=7)
            recent_scores = [score for ts, score in history if ts >= week_ago]
            
            if recent_scores:
                features["risk_score_7d_avg"] = float(np.mean(recent_scores))
                features["risk_score_7d_std"] = float(np.std(recent_scores))
                
                # Calculate trend (linear regression slope)
                if len(recent_scores) >= 2:
                    x = np.arange(len(recent_scores))
                    slope = np.polyfit(x, recent_scores, 1)[0]
                    # Normalize to -1 to 1
                    features["risk_score_trend"] = float(np.clip(slope / 10, -1, 1))
                else:
                    features["risk_score_trend"] = 0.0
            else:
                features["risk_score_7d_avg"] = 50.0
                features["risk_score_7d_std"] = 0.0
                features["risk_score_trend"] = 0.0
        else:
            features["risk_score_7d_avg"] = 50.0
            features["risk_score_7d_std"] = 0.0
            features["risk_score_trend"] = 0.0
        
        # Default temporal features (would be computed from audit logs in production)
        features["days_since_last_change"] = 7.0
        features["changes_last_30d"] = 5.0
        
        return features
    
    async def _extract_edge_features(self, node_id: str) -> Dict[str, float]:
        """Extract edge-based features."""
        features = {
            "inbound_connection_count": 0.0,
            "outbound_connection_count": 0.0,
            "ai_tool_connection_count": 0.0,
            "external_connection_count": 0.0,
            "sensitive_data_flow_count": 0.0,
        }
        
        # Query graph for connections
        if hasattr(self.graph_engine, 'get_node_connections'):
            connections = await self.graph_engine.get_node_connections(node_id)
            if connections:
                features["inbound_connection_count"] = float(connections.get("inbound", 0))
                features["outbound_connection_count"] = float(connections.get("outbound", 0))
                features["ai_tool_connection_count"] = float(connections.get("ai_tools", 0))
                features["external_connection_count"] = float(connections.get("external", 0))
                features["sensitive_data_flow_count"] = float(connections.get("sensitive", 0))
        
        return features
    
    async def _extract_topology_features(self, node_id: str) -> Dict[str, float]:
        """Extract graph topology features."""
        features = {
            "degree_centrality": 0.5,
            "betweenness_centrality": 0.1,
            "clustering_coefficient": 0.3,
            "shortest_path_to_external": 3.0,
            "exposure_path_count": 0.0,
        }
        
        # Query graph for topology metrics
        if hasattr(self.graph_engine, 'get_topology_metrics'):
            metrics = await self.graph_engine.get_topology_metrics(node_id)
            if metrics:
                features.update(metrics)
        
        # Get exposure paths
        if hasattr(self.graph_engine, 'find_exposure_paths'):
            paths = await self.graph_engine.find_exposure_paths(node_id)
            features["exposure_path_count"] = float(len(paths) if paths else 0)
            if paths:
                # Shortest path length
                features["shortest_path_to_external"] = float(min(len(p) for p in paths))
        
        return features
    
    async def _extract_behavioral_features(
        self,
        node_id: str,
        timestamp: datetime
    ) -> Dict[str, float]:
        """Extract behavioral/usage pattern features."""
        # In production, these would come from access logs and audit trails
        features = {
            "access_frequency_24h": 100.0,
            "unique_accessor_count": 10.0,
            "anomalous_access_count": 0.0,
        }
        
        return features
    
    def normalize_features(
        self,
        feature_vector: FeatureVector,
        means: Optional[Dict[str, float]] = None,
        stds: Optional[Dict[str, float]] = None
    ) -> FeatureVector:
        """
        Normalize feature values using z-score normalization.
        
        Args:
            feature_vector: Input feature vector
            means: Optional precomputed means for each feature
            stds: Optional precomputed standard deviations
        
        Returns:
            Normalized FeatureVector
        """
        normalized = {}
        
        for name, value in feature_vector.features.items():
            schema = self._schema_map.get(name)
            
            if means and stds and name in means and name in stds:
                # Use precomputed stats
                mean = means[name]
                std = stds[name]
                normalized[name] = (value - mean) / (std + 1e-8)
            elif schema and schema.min_value is not None and schema.max_value is not None:
                # Min-max normalization as fallback
                range_val = schema.max_value - schema.min_value
                normalized[name] = (value - schema.min_value) / (range_val + 1e-8)
            else:
                normalized[name] = value
        
        return FeatureVector(
            node_id=feature_vector.node_id,
            timestamp=feature_vector.timestamp,
            features=normalized,
            feature_names=feature_vector.feature_names,
            category_breakdown=feature_vector.category_breakdown,
        )
