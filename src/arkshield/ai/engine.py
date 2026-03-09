"""
Arkshield — AI Security Intelligence Engine

Machine learning models for threat detection:
- Behavioral anomaly detection (Isolation Forest + statistical)
- Process risk scoring
- Network threat analysis
- Threat prediction
- Model management and continuous learning
"""

import math
import time
import logging
import random
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, Counter, deque
from datetime import datetime, timezone

from arkshield.telemetry.events import (
    SecurityEvent, EventClass, EventType, Severity,
    ProcessInfo, NetworkInfo
)

logger = logging.getLogger("arkshield.ai")


class BehavioralBaseline:
    """
    Statistical behavioral baseline for processes, users, and network patterns.
    Learns normal behavior and detects deviations.
    """

    def __init__(self, learning_period_days: int = 14):
        self.learning_period = learning_period_days * 86400
        self._start_time = time.time()
        self._process_profiles: Dict[str, Dict] = defaultdict(lambda: {
            'cpu_samples': deque(maxlen=1000),
            'mem_samples': deque(maxlen=1000),
            'net_conn_counts': deque(maxlen=1000),
            'thread_counts': deque(maxlen=1000),
            'seen_count': 0,
            'first_seen': time.time(),
            'parent_processes': Counter(),
            'child_processes': Counter(),
        })
        self._network_profiles: Dict[str, Dict] = defaultdict(lambda: {
            'connection_counts': deque(maxlen=500),
            'ports_used': set(),
            'protocols': Counter(),
            'hourly_distribution': [0] * 24,
        })
        self._is_learning = True

    @property
    def learning_complete(self) -> bool:
        elapsed = time.time() - self._start_time
        if elapsed > self.learning_period:
            self._is_learning = False
        return not self._is_learning

    def update_process(self, proc_name: str, cpu: float, mem: float,
                       net_conns: int, threads: int, parent: str = ""):
        """Update behavioral profile for a process."""
        profile = self._process_profiles[proc_name.lower()]
        profile['cpu_samples'].append(cpu)
        profile['mem_samples'].append(mem)
        profile['net_conn_counts'].append(net_conns)
        profile['thread_counts'].append(threads)
        profile['seen_count'] += 1
        if parent:
            profile['parent_processes'][parent.lower()] += 1

    def update_network(self, process: str, remote_ip: str, port: int, protocol: str):
        """Update network behavioral profile."""
        profile = self._network_profiles[process.lower()]
        profile['connection_counts'].append(1)
        profile['ports_used'].add(port)
        profile['protocols'][protocol] += 1
        hour = datetime.now().hour
        profile['hourly_distribution'][hour] += 1

    def get_anomaly_score(self, proc_name: str, cpu: float, mem: float,
                          net_conns: int, threads: int) -> Tuple[float, List[str]]:
        """
        Calculate anomaly score for current process behavior vs baseline.
        Returns (score 0-100, list of contributing factors).
        """
        name = proc_name.lower()
        if name not in self._process_profiles:
            return 20.0, ["new_process_no_baseline"]

        profile = self._process_profiles[name]
        if profile['seen_count'] < 10:
            return 15.0, ["insufficient_baseline_data"]

        factors = []
        score = 0.0

        # CPU anomaly
        cpu_mean, cpu_std = self._stats(profile['cpu_samples'])
        if cpu_std > 0 and cpu > cpu_mean + 3 * cpu_std:
            score += 25
            factors.append(f"cpu_anomaly ({cpu:.1f}% vs baseline {cpu_mean:.1f}%)")

        # Memory anomaly
        mem_mean, mem_std = self._stats(profile['mem_samples'])
        if mem_std > 0 and mem > mem_mean + 3 * mem_std:
            score += 25
            factors.append(f"memory_anomaly ({mem:.1f}MB vs baseline {mem_mean:.1f}MB)")

        # Network connection anomaly
        net_mean, net_std = self._stats(profile['net_conn_counts'])
        if net_std > 0 and net_conns > net_mean + 3 * net_std:
            score += 25
            factors.append(f"network_anomaly ({net_conns} conns vs baseline {net_mean:.0f})")

        # Thread count anomaly
        thr_mean, thr_std = self._stats(profile['thread_counts'])
        if thr_std > 0 and threads > thr_mean + 3 * thr_std:
            score += 15
            factors.append(f"thread_anomaly ({threads} vs baseline {thr_mean:.0f})")

        return min(score, 100.0), factors

    @staticmethod
    def _stats(samples) -> Tuple[float, float]:
        """Calculate mean and standard deviation."""
        if not samples or len(samples) < 2:
            return 0.0, 0.0
        data = list(samples)
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        return mean, math.sqrt(variance)


class AnomalyDetector:
    """
    Statistical anomaly detection using Isolation Forest principles.
    Implemented without external ML dependencies for portability.
    """

    def __init__(self, n_trees: int = 100, sample_size: int = 256):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self._trees: List[Dict] = []
        self._training_data: List[List[float]] = []
        self._is_fitted = False
        self._feature_names = [
            'cpu_percent', 'memory_mb', 'thread_count',
            'network_connections', 'severity', 'risk_score'
        ]

    def add_sample(self, features: List[float]):
        """Add a training sample."""
        self._training_data.append(features)

    def fit(self):
        """Build the isolation forest."""
        if len(self._training_data) < self.sample_size:
            return False

        self._trees = []
        for _ in range(self.n_trees):
            # Sample subset
            sample = random.sample(self._training_data,
                                   min(self.sample_size, len(self._training_data)))
            tree = self._build_tree(sample, 0, max_depth=int(math.log2(self.sample_size)))
            self._trees.append(tree)

        self._is_fitted = True
        logger.info(f"Isolation Forest fitted with {len(self._training_data)} samples, {self.n_trees} trees")
        return True

    def predict_anomaly_score(self, features: List[float]) -> float:
        """
        Predict anomaly score for a sample.
        Returns score 0-1 where values close to 1 indicate anomalies.
        """
        if not self._is_fitted:
            return 0.5

        avg_path_length = sum(
            self._path_length(features, tree, 0)
            for tree in self._trees
        ) / len(self._trees)

        n = len(self._training_data)
        c_n = 2 * (math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n) if n > 1 else 1

        # Anomaly score formula from Isolation Forest paper
        score = 2 ** (-avg_path_length / c_n) if c_n > 0 else 0.5
        return score

    def _build_tree(self, data: List[List[float]], depth: int, max_depth: int) -> Dict:
        """Recursively build an isolation tree."""
        if depth >= max_depth or len(data) <= 1:
            return {'type': 'leaf', 'size': len(data)}

        n_features = len(data[0]) if data else 0
        if n_features == 0:
            return {'type': 'leaf', 'size': len(data)}

        # Random feature and split point
        feature_idx = random.randint(0, n_features - 1)
        values = [row[feature_idx] for row in data]
        min_val, max_val = min(values), max(values)

        if min_val == max_val:
            return {'type': 'leaf', 'size': len(data)}

        split_val = random.uniform(min_val, max_val)

        left = [row for row in data if row[feature_idx] < split_val]
        right = [row for row in data if row[feature_idx] >= split_val]

        return {
            'type': 'node',
            'feature': feature_idx,
            'split': split_val,
            'left': self._build_tree(left, depth + 1, max_depth),
            'right': self._build_tree(right, depth + 1, max_depth),
        }

    def _path_length(self, sample: List[float], tree: Dict, depth: int) -> float:
        """Calculate path length in an isolation tree."""
        if tree['type'] == 'leaf':
            size = tree['size']
            if size <= 1:
                return depth
            # Average path length adjustment for leaves
            c = 2 * (math.log(size - 1) + 0.5772156649) - (2 * (size - 1) / size) if size > 1 else 0
            return depth + c

        if sample[tree['feature']] < tree['split']:
            return self._path_length(sample, tree['left'], depth + 1)
        else:
            return self._path_length(sample, tree['right'], depth + 1)


class ProcessRiskScorer:
    """
    Calculates risk scores for processes based on multiple signals.
    Combines static analysis, behavioral analysis, and contextual factors.
    """

    def __init__(self):
        self._risk_factors = {
            'lolbin': 20,
            'suspicious_cmdline': 25,
            'suspicious_parent_child': 30,
            'encoded_command': 35,
            'high_entropy': 15,
            'new_process': 10,
            'executable_created': 15,
            'canary_deleted': 40,
            'canary_modified': 40,
            'ransomware_indicator': 40,
            'beacon_detected': 35,
            'injection_indicator': 30,
            'rwx_memory': 25,
            'integrity_violation': 35,
            'persistence': 20,
            'high_port_external': 15,
            'abnormal_memory': 20,
        }

    def score_event(self, event: SecurityEvent) -> float:
        """Calculate comprehensive risk score for an event."""
        score = 0.0

        # Tag-based scoring
        for tag in event.tags:
            if tag in self._risk_factors:
                score += self._risk_factors[tag]

        # Severity-based component
        score += event.severity * 10

        # Threat intel boost
        if event.threat_intel and event.threat_intel.matched_iocs:
            score += 30

        # Network context
        if event.network:
            if event.network.remote_port in {4444, 5555, 31337}:
                score += 20

        # Cap at 100
        return min(score, 100.0)


class ThreatPredictor:
    """
    Predicts likely next attack steps based on observed TTPs.
    Uses MITRE ATT&CK kill chain progression model.
    """

    KILL_CHAIN_PROGRESSION = {
        'initial_access': ['execution', 'persistence'],
        'execution': ['persistence', 'privilege_escalation', 'defense_evasion'],
        'persistence': ['privilege_escalation', 'credential_access'],
        'privilege_escalation': ['credential_access', 'lateral_movement'],
        'defense_evasion': ['credential_access', 'discovery'],
        'credential_access': ['lateral_movement', 'discovery'],
        'discovery': ['lateral_movement', 'collection'],
        'lateral_movement': ['collection', 'command_and_control'],
        'collection': ['exfiltration', 'command_and_control'],
        'command_and_control': ['exfiltration', 'impact'],
        'exfiltration': ['impact'],
        'impact': [],
    }

    def __init__(self):
        self._observed_tactics: List[str] = []
        self._predictions: List[Dict] = []

    def observe_tactic(self, tactic: str):
        """Record an observed MITRE ATT&CK tactic."""
        self._observed_tactics.append(tactic)
        self._generate_predictions()

    def _generate_predictions(self):
        """Generate predictions for likely next attack steps."""
        if not self._observed_tactics:
            return

        latest = self._observed_tactics[-1]
        predicted_next = self.KILL_CHAIN_PROGRESSION.get(latest, [])

        self._predictions = []
        for tactic in predicted_next:
            confidence = 0.7 if tactic == predicted_next[0] else 0.4
            self._predictions.append({
                'predicted_tactic': tactic,
                'confidence': confidence,
                'based_on': latest,
                'recommendation': self._get_recommendation(tactic),
            })

    @staticmethod
    def _get_recommendation(tactic: str) -> str:
        """Get defensive recommendation for a predicted tactic."""
        recommendations = {
            'execution': "Monitor script interpreters and unusual process launches",
            'persistence': "Check registry autoruns, scheduled tasks, and startup folders",
            'privilege_escalation': "Audit service permissions and UAC settings",
            'defense_evasion': "Enable enhanced logging and monitor for log tampering",
            'credential_access': "Protect LSASS, enable Credential Guard",
            'discovery': "Monitor for reconnaissance commands (whoami, net user, etc.)",
            'lateral_movement': "Restrict SMB/WinRM/RDP access, segment network",
            'collection': "Monitor data staging and archive creation",
            'command_and_control': "Analyze outbound traffic for beaconing patterns",
            'exfiltration': "Monitor large data transfers to external destinations",
            'impact': "Ensure backup integrity, enable ransomware protections",
        }
        return recommendations.get(tactic, "Increase monitoring for this tactic")

    @property
    def predictions(self) -> List[Dict]:
        return list(self._predictions)


class AISecurityEngine:
    """
    Main AI engine that orchestrates all ML models and analysis.
    """

    def __init__(self):
        self.baseline = BehavioralBaseline()
        self.anomaly_detector = AnomalyDetector()
        self.risk_scorer = ProcessRiskScorer()
        self.threat_predictor = ThreatPredictor()
        self._events_analyzed = 0
        self._threats_found = 0

    def analyze_event(self, event: SecurityEvent) -> SecurityEvent:
        """Run all AI analysis on an event and update its scores."""
        self._events_analyzed += 1

        # Update behavioral baselines
        if event.process:
            self.baseline.update_process(
                event.process.name,
                event.process.cpu_percent,
                event.process.memory_mb,
                event.process.network_connections,
                event.process.thread_count,
                event.process.parent_name,
            )

        if event.network and event.process:
            self.baseline.update_network(
                event.process.name,
                event.network.remote_ip,
                event.network.remote_port,
                event.network.protocol,
            )

        # Calculate behavioral anomaly score
        if event.process and event.process.name:
            anomaly_score, factors = self.baseline.get_anomaly_score(
                event.process.name,
                event.process.cpu_percent,
                event.process.memory_mb,
                event.process.network_connections,
                event.process.thread_count,
            )
            event.anomaly_score = anomaly_score
            if factors:
                event.metadata['anomaly_factors'] = factors

        # Calculate risk score
        event.risk_score = self.risk_scorer.score_event(event)

        # Feed anomaly detector
        features = self._extract_features(event)
        self.anomaly_detector.add_sample(features)

        # Run anomaly detection if model is fitted
        if self.anomaly_detector._is_fitted:
            isolation_score = self.anomaly_detector.predict_anomaly_score(features)
            # Blend isolation score with other scores
            event.anomaly_score = (event.anomaly_score + isolation_score * 100) / 2

        # Update threat predictor
        if event.mitre and event.mitre.tactic:
            self.threat_predictor.observe_tactic(event.mitre.tactic)

        # Mark as threat if scores are high
        if event.risk_score >= 70 or event.anomaly_score >= 75:
            event.is_threat = True
            self._threats_found += 1

        # Periodically retrain anomaly detector
        if self._events_analyzed % 500 == 0 and self._events_analyzed > 200:
            self.anomaly_detector.fit()

        return event

    def _extract_features(self, event: SecurityEvent) -> List[float]:
        """Extract numerical features from an event for ML analysis."""
        return [
            event.process.cpu_percent if event.process else 0,
            event.process.memory_mb if event.process else 0,
            event.process.thread_count if event.process else 0,
            event.process.network_connections if event.process else 0,
            float(event.severity),
            event.risk_score,
        ]

    def get_predictions(self) -> List[Dict]:
        """Get current threat predictions."""
        return self.threat_predictor.predictions

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "events_analyzed": self._events_analyzed,
            "threats_found": self._threats_found,
            "baseline_complete": self.baseline.learning_complete,
            "anomaly_model_fitted": self.anomaly_detector._is_fitted,
            "process_profiles": len(self.baseline._process_profiles),
            "network_profiles": len(self.baseline._network_profiles),
        }
