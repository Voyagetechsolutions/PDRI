"""
Training Data Loader
====================

Load and prepare training data from various sources.

Sources:
    - Graph database snapshots
    - Historical risk scores
    - Security event logs
    - Labeled incident data

Author: PDRI Team
Version: 1.0.0
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional, Tuple
import numpy as np
import random


@dataclass
class TrainingExample:
    """A single training example."""
    features: np.ndarray
    label: Any
    node_id: str
    timestamp: datetime
    metadata: Dict[str, Any]


@dataclass
class TrainingBatch:
    """A batch of training examples."""
    features: np.ndarray  # Shape: (batch_size, num_features)
    labels: np.ndarray  # Shape: (batch_size,) or (batch_size, num_classes)
    node_ids: List[str]
    timestamps: List[datetime]
    
    def __len__(self) -> int:
        return len(self.node_ids)


@dataclass
class DataSplit:
    """Train/validation/test split."""
    train: List[TrainingExample]
    validation: List[TrainingExample]
    test: List[TrainingExample]
    
    @property
    def sizes(self) -> Dict[str, int]:
        return {
            "train": len(self.train),
            "validation": len(self.validation),
            "test": len(self.test),
        }


class TrainingDataLoader:
    """
    Load and prepare training data for ML models.
    
    Features:
    - Load from graph database
    - Time-based splitting
    - Stratified sampling
    - Batch iteration
    - Data augmentation
    
    Example:
        loader = TrainingDataLoader(graph_engine, feature_engineer)
        data = await loader.load_training_data(start_date, end_date)
        split = loader.split_data(data, train_ratio=0.8)
        
        for batch in loader.batch_iterator(split.train, batch_size=32):
            model.train_step(batch)
    """
    
    def __init__(
        self,
        graph_engine: Any,
        feature_engineer: Any,
        label_source: Optional[Any] = None
    ):
        """
        Initialize data loader.
        
        Args:
            graph_engine: Neo4j graph engine
            feature_engineer: Feature extraction engine
            label_source: Optional source for ground truth labels
        """
        self.graph_engine = graph_engine
        self.feature_engineer = feature_engineer
        self.label_source = label_source
    
    async def load_training_data(
        self,
        start_date: datetime,
        end_date: datetime,
        node_types: Optional[List[str]] = None,
        include_labels: bool = True
    ) -> List[TrainingExample]:
        """
        Load training data from graph database.
        
        Args:
            start_date: Start of training period
            end_date: End of training period
            node_types: Optional filter by node types
            include_labels: Whether to include labels (for supervised learning)
        
        Returns:
            List of training examples
        """
        examples = []
        
        # Get all nodes from graph
        nodes = await self._get_nodes(node_types)
        
        # Extract features for each node at different timestamps
        # (for time-series based training)
        sample_times = self._generate_sample_times(start_date, end_date)
        
        for node in nodes:
            node_id = node.get("id", node.get("node_id"))
            
            for timestamp in sample_times:
                try:
                    # Extract features
                    feature_vector = await self.feature_engineer.extract_features(
                        node_id, timestamp
                    )
                    
                    # Get label if available
                    label = None
                    if include_labels and self.label_source:
                        label = await self._get_label(node_id, timestamp)
                    
                    if label is None and include_labels:
                        # Generate synthetic label based on risk score
                        # In production, labels come from incident database
                        label = self._generate_synthetic_label(feature_vector)
                    
                    examples.append(TrainingExample(
                        features=feature_vector.to_numpy(),
                        label=label,
                        node_id=node_id,
                        timestamp=timestamp,
                        metadata={
                            "node_type": node.get("node_type", "unknown"),
                            "feature_names": feature_vector.feature_names,
                        },
                    ))
                except Exception as e:
                    # Log and continue
                    print(f"Error loading data for {node_id} at {timestamp}: {e}")
        
        return examples
    
    async def _get_nodes(
        self,
        node_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Get nodes from graph."""
        if hasattr(self.graph_engine, 'get_all_nodes'):
            nodes = await self.graph_engine.get_all_nodes(node_types)
            return nodes
        
        # Fallback: return mock data
        return [
            {"id": f"node-{i}", "node_type": "DataStore"}
            for i in range(100)
        ]
    
    def _generate_sample_times(
        self,
        start: datetime,
        end: datetime,
        interval_hours: int = 24
    ) -> List[datetime]:
        """Generate sample timestamps."""
        times = []
        current = start
        while current <= end:
            times.append(current)
            current += timedelta(hours=interval_hours)
        return times
    
    async def _get_label(
        self,
        node_id: str,
        timestamp: datetime
    ) -> Optional[Any]:
        """Get ground truth label for a node at a timestamp."""
        if self.label_source and hasattr(self.label_source, 'get_label'):
            return await self.label_source.get_label(node_id, timestamp)
        return None
    
    def _generate_synthetic_label(self, feature_vector: Any) -> int:
        """Generate synthetic label for unsupervised pre-training."""
        # Binary classification: high risk (1) vs normal (0)
        risk_score = feature_vector.features.get("current_risk_score", 50)
        return 1 if risk_score >= 70 else 0
    
    def split_data(
        self,
        examples: List[TrainingExample],
        train_ratio: float = 0.7,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        stratify: bool = True,
        time_based: bool = False,
        shuffle: bool = True,
        seed: int = 42
    ) -> DataSplit:
        """
        Split data into train/validation/test sets.
        
        Args:
            examples: All training examples
            train_ratio: Proportion for training
            val_ratio: Proportion for validation
            test_ratio: Proportion for testing
            stratify: Whether to stratify by label
            time_based: If True, split by time (earlier=train, later=test)
            shuffle: Whether to shuffle before splitting
            seed: Random seed for reproducibility
        
        Returns:
            DataSplit with train/val/test sets
        """
        assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 0.001
        
        if time_based:
            return self._time_based_split(examples, train_ratio, val_ratio)
        
        if shuffle:
            random.seed(seed)
            examples = examples.copy()
            random.shuffle(examples)
        
        if stratify:
            return self._stratified_split(examples, train_ratio, val_ratio, test_ratio, seed)
        
        # Simple random split
        n = len(examples)
        train_end = int(n * train_ratio)
        val_end = train_end + int(n * val_ratio)
        
        return DataSplit(
            train=examples[:train_end],
            validation=examples[train_end:val_end],
            test=examples[val_end:],
        )
    
    def _time_based_split(
        self,
        examples: List[TrainingExample],
        train_ratio: float,
        val_ratio: float
    ) -> DataSplit:
        """Split by timestamp (temporal split)."""
        # Sort by timestamp
        sorted_examples = sorted(examples, key=lambda x: x.timestamp)
        
        n = len(sorted_examples)
        train_end = int(n * train_ratio)
        val_end = train_end + int(n * val_ratio)
        
        return DataSplit(
            train=sorted_examples[:train_end],
            validation=sorted_examples[train_end:val_end],
            test=sorted_examples[val_end:],
        )
    
    def _stratified_split(
        self,
        examples: List[TrainingExample],
        train_ratio: float,
        val_ratio: float,
        test_ratio: float,
        seed: int
    ) -> DataSplit:
        """Split with stratification by label."""
        random.seed(seed)
        
        # Group by label
        by_label: Dict[Any, List[TrainingExample]] = {}
        for ex in examples:
            label = ex.label
            if label not in by_label:
                by_label[label] = []
            by_label[label].append(ex)
        
        train, val, test = [], [], []
        
        for label_examples in by_label.values():
            random.shuffle(label_examples)
            n = len(label_examples)
            train_end = int(n * train_ratio)
            val_end = train_end + int(n * val_ratio)
            
            train.extend(label_examples[:train_end])
            val.extend(label_examples[train_end:val_end])
            test.extend(label_examples[val_end:])
        
        # Shuffle each set
        random.shuffle(train)
        random.shuffle(val)
        random.shuffle(test)
        
        return DataSplit(train=train, validation=val, test=test)
    
    def batch_iterator(
        self,
        examples: List[TrainingExample],
        batch_size: int = 32,
        shuffle: bool = True,
        drop_last: bool = False
    ) -> Iterator[TrainingBatch]:
        """
        Iterate over examples in batches.
        
        Args:
            examples: List of training examples
            batch_size: Number of examples per batch
            shuffle: Whether to shuffle before iterating
            drop_last: Whether to drop the last incomplete batch
        
        Yields:
            TrainingBatch objects
        """
        if shuffle:
            examples = examples.copy()
            random.shuffle(examples)
        
        n = len(examples)
        
        for i in range(0, n, batch_size):
            batch_examples = examples[i:i + batch_size]
            
            if drop_last and len(batch_examples) < batch_size:
                break
            
            yield TrainingBatch(
                features=np.stack([ex.features for ex in batch_examples]),
                labels=np.array([ex.label for ex in batch_examples]),
                node_ids=[ex.node_id for ex in batch_examples],
                timestamps=[ex.timestamp for ex in batch_examples],
            )
    
    def augment_data(
        self,
        examples: List[TrainingExample],
        noise_std: float = 0.01,
        num_augmented: int = 1
    ) -> List[TrainingExample]:
        """
        Augment training data with noise.
        
        Args:
            examples: Original examples
            noise_std: Standard deviation of Gaussian noise
            num_augmented: Number of augmented copies per example
        
        Returns:
            Original + augmented examples
        """
        augmented = list(examples)
        
        for ex in examples:
            for _ in range(num_augmented):
                noise = np.random.normal(0, noise_std, ex.features.shape)
                new_features = ex.features + noise
                
                augmented.append(TrainingExample(
                    features=new_features,
                    label=ex.label,
                    node_id=ex.node_id,
                    timestamp=ex.timestamp,
                    metadata={**ex.metadata, "augmented": True},
                ))
        
        return augmented
    
    def balance_classes(
        self,
        examples: List[TrainingExample],
        strategy: str = "oversample"  # "oversample" or "undersample"
    ) -> List[TrainingExample]:
        """
        Balance class distribution.
        
        Args:
            examples: Training examples
            strategy: "oversample" minority or "undersample" majority
        
        Returns:
            Balanced examples
        """
        # Group by label
        by_label: Dict[Any, List[TrainingExample]] = {}
        for ex in examples:
            if ex.label not in by_label:
                by_label[ex.label] = []
            by_label[ex.label].append(ex)
        
        counts = {label: len(exs) for label, exs in by_label.items()}
        
        if strategy == "oversample":
            target_count = max(counts.values())
        else:
            target_count = min(counts.values())
        
        balanced = []
        for label, label_examples in by_label.items():
            if strategy == "oversample" and len(label_examples) < target_count:
                # Repeat with replacement
                balanced.extend(
                    random.choices(label_examples, k=target_count)
                )
            elif strategy == "undersample" and len(label_examples) > target_count:
                balanced.extend(random.sample(label_examples, target_count))
            else:
                balanced.extend(label_examples)
        
        random.shuffle(balanced)
        return balanced
