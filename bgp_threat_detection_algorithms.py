# Advanced BGP Threat Detection Algorithms
# Based on current research and industry practices

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import networkx as nx
import ipaddress
import logging
from typing import Dict, List, Tuple, Optional, Set
import asyncio
from dataclasses import dataclass
from enum import Enum

class ThreatType(Enum):
    HIJACK = "hijack"
    ROUTE_LEAK = "route_leak" 
    BOGON = "bogon"
    GEOPOLITICAL = "geopolitical"
    MOAS_CONFLICT = "moas_conflict"
    PATH_ANOMALY = "path_anomaly"

@dataclass
class BGPUpdate:
    timestamp: datetime
    peer_asn: int
    prefix: str
    as_path: List[int]
    next_hop: str
    origin_asn: int
    collector: str
    withdrawn: bool = False

@dataclass
class ThreatEvent:
    threat_type: ThreatType
    severity: str  # critical, high, medium, low
    confidence: float  # 0.0 to 1.0
    prefix: str
    origin_asn: int
    description: str
    evidence: Dict
    detected_at: datetime

class AdvancedThreatDetector:
    """
    Comprehensive BGP threat detection using multiple algorithms:
    1. MOAS (Multiple Origin AS) Detection
    2. ML-based Anomaly Detection  
    3. RPKI Validation
    4. Geopolitical Analysis
    5. Path Validation
    """
    
    def __init__(self, redis_client, rpki_validator=None):
        self.redis = redis_client
        self.rpki_validator = rpki_validator
        
        # Historical data storage
        self.prefix_origins = defaultdict(set)  # prefix -> set of origin ASNs
        self.asn_relationships = {}  # ASN -> {'peers': set, 'customers': set, 'providers': set}
        self.geopolitical_risks = {}  # country_code -> risk_score
        
        # ML models
        self.anomaly_detector = None
        self.hijack_classifier = None
        self.feature_scaler = StandardScaler()
        
        # Graph for topology analysis
        self.bgp_graph = nx.Graph()
        
        # Initialize models
        self._initialize_models()
        self._load_geopolitical_data()
    
    def _initialize_models(self):
        """Initialize ML models for anomaly detection"""
        # Isolation Forest for unsupervised anomaly detection
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Random Forest for supervised hijack classification
        self.hijack_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42
        )
    
    def _load_geopolitical_data(self):
        """Load geopolitical risk scores for countries"""
        # In production, this would load from a threat intelligence feed
        high_risk_countries = [
            'CN', 'RU', 'KP', 'IR', 'PK',  # Example high-risk countries
        ]
        medium_risk_countries = [
            'BD', 'VE', 'BY', 'MM', 'AF'   # Example medium-risk countries
        ]
        
        for country in high_risk_countries:
            self.geopolitical_risks[country] = 0.8
        for country in medium_risk_countries:
            self.geopolitical_risks[country] = 0.5
    
    async def analyze_bgp_update(self, update: BGPUpdate) -> List[ThreatEvent]:
        """Main entry point - analyze a BGP update for threats"""
        threats = []
        
        # Run all detection algorithms
        threats.extend(await self._detect_moas_conflict(update))
        threats.extend(await self._detect_prefix_hijack(update))
        threats.extend(await self._detect_route_leak(update))
        threats.extend(await self._detect_bogon_announcement(update))
        threats.extend(await self._detect_geopolitical_anomaly(update))
        threats.extend(await self._detect_path_anomaly(update))
        
        # Update historical data
        await self._update_historical_data(update)
        
        return threats
    
    async def _detect_moas_conflict(self, update: BGPUpdate) -> List[ThreatEvent]:
        """
        MOAS (Multiple Origin AS) Detection
        Based on: "BGP prefix hijack detection algorithm based on MOAS event feature"
        """
        threats = []
        prefix = update.prefix
        origin_asn = update.origin_asn
        
        # Get historical origins for this prefix
        historical_key = f"prefix_origins:{prefix}"
        historical_origins = self.redis.smembers(historical_key)
        
        if historical_origins:
            historical_origins = {int(asn) for asn in historical_origins}
            
            # Check if this is a new origin
            if origin_asn not in historical_origins:
                # Calculate MOAS conflict score
                conflict_score = self._calculate_moas_score(
                    prefix, origin_asn, historical_origins, update
                )
                
                if conflict_score > 0.7:  # High confidence threshold
                    threats.append(ThreatEvent(
                        threat_type=ThreatType.MOAS_CONFLICT,
                        severity="high" if conflict_score > 0.9 else "medium",
                        confidence=conflict_score,
                        prefix=prefix,
                        origin_asn=origin_asn,
                        description=f"MOAS conflict: {prefix} announced by new ASN {origin_asn}",
                        evidence={
                            "historical_origins": list(historical_origins),
                            "new_origin": origin_asn,
                            "moas_score": conflict_score,
                            "observation_points": await self._get_observation_points(prefix)
                        },
                        detected_at=update.timestamp
                    ))
        
        return threats
    
    def _calculate_moas_score(self, prefix: str, new_origin: int, 
                            historical_origins: Set[int], update: BGPUpdate) -> float:
        """
        Calculate MOAS conflict score based on multiple factors:
        - Number of observation points seeing the conflict
        - Duration since first historical announcement
        - AS reputation scores
        - Prefix specificity changes
        """
        score = 0.0
        
        # Factor 1: Multiple observation points (higher score = more suspicious)
        observation_points = len(self._get_collectors_seeing_prefix(prefix))
        if observation_points > 3:
            score += 0.3
        
        # Factor 2: Sudden appearance without gradual rollout
        recent_announcements = self._get_recent_announcements(prefix, hours=24)
        if len(recent_announcements) < 2:  # Sudden appearance
            score += 0.4
        
        # Factor 3: Check if new origin has suspicious characteristics
        if self._is_suspicious_asn(new_origin):
            score += 0.3
        
        # Factor 4: Prefix specificity - more specific prefixes are often hijacks
        if self._is_more_specific_than_historical(prefix, historical_origins):
            score += 0.2
        
        return min(score, 1.0)
    
    async def _detect_prefix_hijack(self, update: BGPUpdate) -> List[ThreatEvent]:
        """
        Advanced prefix hijack detection using ML and heuristics
        Based on research from BGPWatch and Cloudflare's detection system
        """
        threats = []
        
        # Extract features for ML model
        features = await self._extract_hijack_features(update)
        
        if self.hijack_classifier and len(features) > 0:
            # Normalize features
            features_scaled = self.feature_scaler.transform([features])
            
            # Get prediction and probability
            prediction = self.hijack_classifier.predict(features_scaled)[0]
            probability = self.hijack_classifier.predict_proba(features_scaled)[0]
            
            if prediction == 1:  # Hijack detected
                confidence = max(probability)
                
                threats.append(ThreatEvent(
                    threat_type=ThreatType.HIJACK,
                    severity=self._severity_from_confidence(confidence),
                    confidence=confidence,
                    prefix=update.prefix,
                    origin_asn=update.origin_asn,
                    description=f"ML-detected hijack of {update.prefix}",
                    evidence={
                        "ml_confidence": confidence,
                        "features": dict(zip(self._get_feature_names(), features)),
                        "as_path": update.as_path
                    },
                    detected_at=update.timestamp
                ))
        
        return threats
    
    async def _extract_hijack_features(self, update: BGPUpdate) -> List[float]:
        """
        Extract features for ML-based hijack detection
        Features based on academic research and industry best practices
        """
        features = []
        
        # Feature 1: AS Path length anomaly
        prefix = update.prefix
        historical_paths = await self._get_historical_paths(prefix)
        if historical_paths:
            avg_historical_length = np.mean([len(path) for path in historical_paths])
            current_length = len(update.as_path)
            features.append(abs(current_length - avg_historical_length))
        else:
            features.append(0.0)
        
        # Feature 2: Origin AS reputation score
        origin_reputation = await self._get_asn_reputation(update.origin_asn)
        features.append(1.0 - origin_reputation)  # Lower reputation = higher suspicion
        
        # Feature 3: Prefix specificity compared to historical
        specificity_change = self._calculate_prefix_specificity_change(prefix)
        features.append(specificity_change)
        
        # Feature 4: Geopolitical routing anomaly
        geo_anomaly = await self._calculate_geo_anomaly_score(update.as_path)
        features.append(geo_anomaly)
        
        # Feature 5: RPKI validation status
        rpki_score = await self._get_rpki_validation_score(prefix, update.origin_asn)
        features.append(1.0 - rpki_score)  # Invalid RPKI = higher suspicion
        
        # Feature 6: Temporal anomaly (sudden announcement pattern)
        temporal_score = await self._calculate_temporal_anomaly(prefix, update.timestamp)
        features.append(temporal_score)
        
        # Feature 7: AS relationship violations
        relationship_violations = self._count_relationship_violations(update.as_path)
        features.append(relationship_violations)
        
        return features
    
    async def _detect_route_leak(self, update: BGPUpdate) -> List[ThreatEvent]:
        """
        Detect route leaks using valley-free routing principles
        A route leak occurs when a route is announced to peers/providers 
        when it should only go to customers
        """
        threats = []
        as_path = update.as_path
        
        if len(as_path) < 3:
            return threats
        
        violations = []
        
        # Check for valley-free violations
        for i in range(len(as_path) - 2):
            current_asn = as_path[i]
            next_asn = as_path[i + 1]
            following_asn = as_path[i + 2]
            
            # Get relationships
            curr_to_next = await self._get_as_relationship(current_asn, next_asn)
            next_to_following = await self._get_as_relationship(next_asn, following_asn)
            
            # Valley-free violation: customer -> provider -> customer
            if (curr_to_next == "customer" and 
                next_to_following == "customer"):
                violations.append({
                    "position": i,
                    "asns": [current_asn, next_asn, following_asn],
                    "violation_type": "valley_free"
                })
        
        if violations:
            confidence = min(len(violations) * 0.3, 1.0)
            threats.append(ThreatEvent(
                threat_type=ThreatType.ROUTE_LEAK,
                severity=self._severity_from_confidence(confidence),
                confidence=confidence,
                prefix=update.prefix,
                origin_asn=update.origin_asn,
                description=f"Route leak detected in AS path",
                evidence={
                    "violations": violations,
                    "as_path": as_path
                },
                detected_at=update.timestamp
            ))
        
        return threats
    
    async def _detect_bogon_announcement(self, update: BGPUpdate) -> List[ThreatEvent]:
        """Detect announcements of bogon prefixes (shouldn't be routed)"""
        threats = []
        prefix = update.prefix
        
        try:
            network = ipaddress.ip_network(prefix)
            
            # Check against bogon lists
            is_bogon = (
                network.is_private or 
                network.is_reserved or 
                network.is_loopback or
                network.is_multicast or
                network.is_link_local or
                str(network).startswith(('0.', '127.', '169.254.', '224.'))
            )
            
            if is_bogon:
                threats.append(ThreatEvent(
                    threat_type=ThreatType.BOGON,
                    severity="high",
                    confidence=1.0,
                    prefix=prefix,
                    origin_asn=update.origin_asn,
                    description=f"Bogon prefix announcement: {prefix}",
                    evidence={
                        "prefix_type": "private/reserved",
                        "network_info": str(network)
                    },
                    detected_at=update.timestamp
                ))
        
        except ValueError:
            # Invalid prefix format
            threats.append(ThreatEvent(
                threat_type=ThreatType.BOGON,
                severity="medium",
                confidence=0.8,
                prefix=prefix,
                origin_asn=update.origin_asn,
                description=f"Invalid prefix format: {prefix}",
                evidence={"error": "invalid_prefix_format"},
                detected_at=update.timestamp
            ))
        
        return threats
    
    async def _detect_geopolitical_anomaly(self, update: BGPUpdate) -> List[ThreatEvent]:
        """
        Detect geopolitically suspicious routing patterns
        - Traffic through high-risk countries
        - Unusual detours through sensitive regions
        """
        threats = []
        as_path = update.as_path
        
        # Get country for each ASN in path
        path_countries = []
        for asn in as_path:
            country = await self._get_asn_country(asn)
            if country:
                path_countries.append(country)
        
        # Check for high-risk countries in path
        risk_score = 0.0
        high_risk_countries = []
        
        for country in path_countries:
            if country in self.geopolitical_risks:
                country_risk = self.geopolitical_risks[country]
                risk_score += country_risk
                if country_risk > 0.7:
                    high_risk_countries.append(country)
        
        # Normalize risk score
        risk_score = min(risk_score / len(path_countries), 1.0) if path_countries else 0.0
        
        # Check for suspicious detours
        detour_score = await self._calculate_geo_detour_score(path_countries, update.prefix)
        
        total_risk = (risk_score + detour_score) / 2
        
        if total_risk > 0.6:
            threats.append(ThreatEvent(
                threat_type=ThreatType.GEOPOLITICAL,
                severity=self._severity_from_confidence(total_risk),
                confidence=total_risk,
                prefix=update.prefix,
                origin_asn=update.origin_asn,
                description=f"Geopolitically suspicious routing via {', '.join(high_risk_countries)}",
                evidence={
                    "path_countries": path_countries,
                    "high_risk_countries": high_risk_countries,
                    "risk_score": risk_score,
                    "detour_score": detour_score
                },
                detected_at=update.timestamp
            ))
        
        return threats
    
    async def _detect_path_anomaly(self, update: BGPUpdate) -> List[ThreatEvent]:
        """
        Detect unusual AS path patterns using graph analysis
        Based on: "Comparing Machine Learning Algorithms for BGP Anomaly Detection using Graph Features"
        """
        threats = []
        as_path = update.as_path
        
        if len(as_path) < 2:
            return threats
        
        # Calculate graph-based features
        features = []
        
        # Feature 1: Path length deviation from normal
        prefix = update.prefix
        normal_lengths = await self._get_normal_path_lengths(prefix)
        if normal_lengths:
            current_length = len(as_path)
            avg_normal = np.mean(normal_lengths)
            std_normal = np.std(normal_lengths)
            if std_normal > 0:
                z_score = abs(current_length - avg_normal) / std_normal
                features.append(z_score)
            else:
                features.append(0.0)
        
        # Feature 2: Unusual AS adjacencies
        unusual_adjacencies = 0
        for i in range(len(as_path) - 1):
            asn1, asn2 = as_path[i], as_path[i + 1]
            if not await self._is_common_adjacency(asn1, asn2):
                unusual_adjacencies += 1
        
        adjacency_ratio = unusual_adjacencies / (len(as_path) - 1) if len(as_path) > 1 else 0
        features.append(adjacency_ratio)
        
        # Feature 3: Graph centrality anomalies
        centrality_score = await self._calculate_path_centrality_anomaly(as_path)
        features.append(centrality_score)
        
        # Combine features into anomaly score
        if features:
            anomaly_score = np.mean(features)
            
            if anomaly_score > 0.7:
                threats.append(ThreatEvent(
                    threat_type=ThreatType.PATH_ANOMALY,
                    severity=self._severity_from_confidence(anomaly_score),
                    confidence=anomaly_score,
                    prefix=update.prefix,
                    origin_asn=update.origin_asn,
                    description=f"Unusual AS path pattern detected",
                    evidence={
                        "anomaly_score": anomaly_score,
                        "unusual_adjacencies": unusual_adjacencies,
                        "path_length": len(as_path),
                        "as_path": as_path
                    },
                    detected_at=update.timestamp
                ))
        
        return threats
    
    # Helper methods (simplified implementations)
    
    def _severity_from_confidence(self, confidence: float) -> str:
        """Convert confidence score to severity level"""
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"
    
    async def _get_asn_country(self, asn: int) -> Optional[str]:
        """Get country code for an ASN"""
        # In production, this would query a GeoIP database
        # For now, return mock data based on ASN ranges
        if 4134 <= asn <= 4809:  # China Telecom range (example)
            return "CN"
        elif 12389 <= asn <= 12715:  # Russian ASNs (example)
            return "RU"
        return "US"  # Default
    
    async def _get_asn_reputation(self, asn: int) -> float:
        """Get reputation score for an ASN (0.0 = bad, 1.0 = good)"""
        # This would integrate with threat intelligence feeds
        # Check against known malicious ASNs, spam sources, etc.
        return 0.8  # Default neutral-good reputation
    
    async def _get_rpki_validation_score(self, prefix: str, origin_asn: int) -> float:
        """Get RPKI validation score"""
        if self.rpki_validator:
            result = await self.rpki_validator.validate(prefix, origin_asn)
            return 1.0 if result == "valid" else 0.0
        return 0.5  # Unknown
    
    async def _update_historical_data(self, update: BGPUpdate):
        """Update historical data for future analysis"""
        prefix = update.prefix
        origin_asn = update.origin_asn
        
        # Update prefix origins
        historical_key = f"prefix_origins:{prefix}"
        self.redis.sadd(historical_key, origin_asn)
        self.redis.expire(historical_key, 86400 * 30)  # 30 days
        
        # Update AS path adjacencies
        for i in range(len(update.as_path) - 1):
            asn1, asn2 = update.as_path[i], update.as_path[i + 1]
            adjacency_key = f"as_adjacency:{min(asn1, asn2)}:{max(asn1, asn2)}"
            self.redis.incr(adjacency_key)
            self.redis.expire(adjacency_key, 86400 * 7)  # 7 days
    
    def train_models(self, historical_data: pd.DataFrame):
        """Train ML models on historical BGP data"""
        # This would use labeled historical data to train the classifiers
        # Features: path length, origin reputation, RPKI status, etc.
        # Labels: hijack/normal, leak/normal, etc.
        
        if len(historical_data) > 1000:  # Minimum data requirement
            features = historical_data.drop(['label'], axis=1)
            labels = historical_data['label']
            
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=0.2, random_state=42
            )
            
            # Fit scaler and transform features
            X_train_scaled = self.feature_scaler.fit_transform(X_train)
            X_test_scaled = self.feature_scaler.transform(X_test)
            
            # Train supervised classifier
            self.hijack_classifier.fit(X_train_scaled, y_train)
            
            # Train unsupervised anomaly detector
            normal_data = X_train_scaled[y_train == 0]  # Normal traffic only
            self.anomaly_detector.fit(normal_data)
            
            # Evaluate performance
            accuracy = self.hijack_classifier.score(X_test_scaled, y_test)
            logging.info(f"Hijack classifier accuracy: {accuracy:.3f}")

# Example usage and integration
class BGPThreatMonitor:
    """Main monitoring service that orchestrates threat detection"""
    
    def __init__(self, redis_client):
        self.detector = AdvancedThreatDetector(redis_client)
        self.threat_callbacks = []
    
    def add_threat_callback(self, callback):
        """Add callback function to handle detected threats"""
        self.threat_callbacks.append(callback)
    
    async def process_bgp_stream(self, bgp_stream):
        """Process live BGP stream and detect threats"""
        async for raw_update in bgp_stream:
            try:
                # Parse BGP update
                update = self._parse_bgp_update(raw_update)
                
                # Run threat detection
                threats = await self.detector.analyze_bgp_update(update)
                
                # Handle detected threats
                for threat in threats:
                    await self._handle_threat(threat)
                    
            except Exception as e:
                logging.error(f"Error processing BGP update: {e}")
    
    async def _handle_threat(self, threat: ThreatEvent):
        """Handle a detected threat event"""
        # Log the threat
        logging.warning(f"Threat detected: {threat.threat_type.value} - {threat.description}")
        
        # Call registered callbacks
        for callback in self.threat_callbacks:
            try:
                await callback(threat)
            except Exception as e:
                logging.error(f"Error in threat callback: {e}")
    
    def _parse_bgp_update(self, raw_update: dict) -> BGPUpdate:
        """Parse raw BGP update into structured format"""
        return BGPUpdate(
            timestamp=datetime.fromtimestamp(raw_update['timestamp']),
            peer_asn=raw_update['peer_asn'],
            prefix=raw_update['prefix'],
            as_path=[int(asn) for asn in raw_update['as_path'].split()],
            next_hop=raw_update['next_hop'],
            origin_asn=int(raw_update['as_path'].split()[-1]) if raw_update['as_path'] else 0,
            collector=raw_update['collector'],
            withdrawn=raw_update.get('type') == 'W'
        )