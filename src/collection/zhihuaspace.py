#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK Similarity Clustering Module

Clusters similar APK samples based on various features.
Part of the Profit2Pitfall toolkit.
"""

import os
import re
import json
import argparse
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Any, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SimilarityClusterer:
    """Clusters APK samples by similarity features."""
    
    def __init__(self):
        self.samples: Dict[str, Dict[str, Any]] = {}
        self.clusters: Dict[str, List[str]] = {}
        
    def add_sample(
        self,
        sample_id: str,
        features: Dict[str, Any]
    ):
        """
        Add a sample with its features.
        
        Args:
            sample_id: Unique sample identifier
            features: Dictionary of feature values
        """
        self.samples[sample_id] = features
        
    def load_samples_from_directory(
        self,
        directory: str,
        feature_extractor: callable = None
    ) -> int:
        """
        Load samples from a directory.
        
        Args:
            directory: Directory containing sample info files
            feature_extractor: Function to extract features from file content
            
        Returns:
            Number of samples loaded
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.error(f"Directory not found: {directory}")
            return 0
            
        count = 0
        for file_path in dir_path.glob("*.txt"):
            sample_id = file_path.stem
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                if feature_extractor:
                    features = feature_extractor(content)
                else:
                    features = self._default_feature_extractor(content)
                    
                self.add_sample(sample_id, features)
                count += 1
                
            except Exception as e:
                logger.debug(f"Error loading {file_path}: {e}")
                
        logger.info(f"Loaded {count} samples")
        return count
        
    def _default_feature_extractor(self, content: str) -> Dict[str, Any]:
        """Default feature extractor for APK info files."""
        features = {
            'package_name': '',
            'permissions': [],
            'activities': [],
            'services': []
        }
        
        # Extract package name
        match = re.search(r"package: name='([^']+)'", content)
        if match:
            features['package_name'] = match.group(1)
            
        # Extract permissions
        permissions = re.findall(r"uses-permission: name='([^']+)'", content)
        features['permissions'] = permissions
        
        # Extract activities
        activities = re.findall(r"activity: name='([^']+)'", content)
        features['activities'] = activities
        
        return features
        
    def cluster_by_package_prefix(self, prefix_length: int = 2) -> Dict[str, List[str]]:
        """
        Cluster samples by package name prefix.
        
        Args:
            prefix_length: Number of package segments to use
            
        Returns:
            Dictionary of prefix -> sample IDs
        """
        clusters = defaultdict(list)
        
        for sample_id, features in self.samples.items():
            package = features.get('package_name', '')
            if package:
                parts = package.split('.')[:prefix_length]
                prefix = '.'.join(parts)
                clusters[prefix].append(sample_id)
                
        self.clusters = dict(clusters)
        return self.clusters
        
    def cluster_by_permissions(
        self,
        min_common: int = 5
    ) -> Dict[str, List[str]]:
        """
        Cluster samples by common permission sets.
        
        Args:
            min_common: Minimum common permissions for clustering
            
        Returns:
            Dictionary of permission signature -> sample IDs
        """
        clusters = defaultdict(list)
        
        for sample_id, features in self.samples.items():
            perms = sorted(features.get('permissions', []))
            # Create signature from first N permissions
            sig = ','.join(perms[:min_common]) if len(perms) >= min_common else ','.join(perms)
            clusters[sig].append(sample_id)
            
        # Filter out single-sample clusters
        self.clusters = {k: v for k, v in clusters.items() if len(v) > 1}
        return self.clusters
        
    def find_similar_samples(
        self,
        sample_id: str,
        similarity_threshold: float = 0.7
    ) -> List[Tuple[str, float]]:
        """
        Find samples similar to a given sample.
        
        Args:
            sample_id: Sample to find similar samples for
            similarity_threshold: Minimum similarity score
            
        Returns:
            List of (sample_id, similarity_score) tuples
        """
        if sample_id not in self.samples:
            return []
            
        target = self.samples[sample_id]
        target_perms = set(target.get('permissions', []))
        
        similar = []
        for other_id, features in self.samples.items():
            if other_id == sample_id:
                continue
                
            other_perms = set(features.get('permissions', []))
            
            if not target_perms or not other_perms:
                continue
                
            # Jaccard similarity
            intersection = len(target_perms & other_perms)
            union = len(target_perms | other_perms)
            similarity = intersection / union if union > 0 else 0
            
            if similarity >= similarity_threshold:
                similar.append((other_id, similarity))
                
        return sorted(similar, key=lambda x: x[1], reverse=True)
        
    def export_clusters(self, output_file: str):
        """Export clusters to file."""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'cluster_count': len(self.clusters),
                'total_samples': len(self.samples),
                'clusters': self.clusters
            }, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Clusters saved to: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Cluster similar APK samples')
    parser.add_argument('--input-dir', '-i', required=True, help='Directory with sample info files')
    parser.add_argument('--method', '-m', choices=['package', 'permissions'], default='package',
                       help='Clustering method')
    parser.add_argument('--output', '-o', default='clusters.json', help='Output file')
    
    args = parser.parse_args()
    
    clusterer = SimilarityClusterer()
    count = clusterer.load_samples_from_directory(args.input_dir)
    
    if count == 0:
        print("No samples loaded")
        return
        
    if args.method == 'package':
        clusters = clusterer.cluster_by_package_prefix()
    else:
        clusters = clusterer.cluster_by_permissions()
        
    clusterer.export_clusters(args.output)
    
    print(f"\nClustering complete:")
    print(f"  Samples: {len(clusterer.samples)}")
    print(f"  Clusters: {len(clusters)}")
    
    # Show top clusters
    sorted_clusters = sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True)
    print(f"\nTop clusters:")
    for prefix, samples in sorted_clusters[:10]:
        print(f"  {prefix}: {len(samples)} samples")


if __name__ == "__main__":
    main()
