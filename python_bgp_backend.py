# Python BGP Backend Architecture
# Using FastAPI, SQLAlchemy, and specialized BGP libraries

from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import json
import redis
from datetime import datetime, timedelta
import pybgpstream
import requests
from ipaddress import ip_network, AddressValueError
import logging

# =============================================
# FastAPI App Setup
# =============================================

app = FastAPI(title="BGP Threat Intelligence API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================
# Database Models
# =============================================

Base = declarative_base()
engine = create_engine("postgresql://user:pass@localhost/bgp_intel")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class ASNInfo(Base):
    __tablename__ = "asn_info"
    
    asn = Column(Integer, primary_key=True)
    name = Column(String)
    country = Column(String)
    org = Column(String)
    threat_score = Column(Float, default=0.0)
    last_updated = Column(DateTime, default=datetime.utcnow)
    metadata = Column(JSON)

class BGPRoute(Base):
    __tablename__ = "bgp_routes"
    
    id = Column(Integer, primary_key=True)
    prefix = Column(String)
    origin_asn = Column(Integer)
    as_path = Column(JSON)  # Store as JSON array
    next_hop = Column(String)
    timestamp = Column(DateTime)
    peer_asn = Column(Integer)
    collector = Column(String)

class ThreatEvent(Base):
    __tablename__ = "threat_events"
    
    id = Column(Integer, primary_key=True)
    event_type = Column(String)  # hijack, leak, anomaly
    prefix = Column(String)
    origin_asn = Column(Integer)
    expected_origin = Column(Integer)
    as_path = Column(JSON)
    severity = Column(String)
    detected_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="active")
    metadata = Column(JSON)

# =============================================
# Pydantic Models (API Schemas)
# =============================================

class ASNResponse(BaseModel):
    asn: int
    name: str
    country: str
    org: str
    threat_score: float
    threat_level: str
    links: List[Dict[str, Any]]

class ThreatEventResponse(BaseModel):
    id: int
    event_type: str
    prefix: str
    origin_asn: int
    severity: str
    detected_at: datetime
    description: str

class BGPPathResponse(BaseModel):
    source_asn: int
    dest_asn: int
    paths: List[List[int]]
    path_analysis: Dict[str, Any]

# =============================================
# BGP Data Services
# =============================================

class RIPEService:
    """Service for interacting with RIPE RIS APIs"""
    
    BASE_URL = "https://stat.ripe.net/data"
    
    @staticmethod
    async def get_asn_info(asn: int) -> Dict:
        """Get ASN information from RIPE"""
        try:
            # ASN overview
            response = requests.get(
                f"{RIPEService.BASE_URL}/as-overview/data.json",
                params={"resource": asn}
            )
            overview = response.json()
            
            # Country info
            country_response = requests.get(
                f"{RIPEService.BASE_URL}/geoloc/data.json",
                params={"resource": asn}
            )
            country_data = country_response.json()
            
            return {
                "asn": asn,
                "name": overview["data"]["holder"],
                "country": country_data["data"]["locations"][0]["country"] if country_data["data"]["locations"] else "Unknown",
                "org": overview["data"]["holder"],
                "prefixes": overview["data"]["announced"]
            }
        except Exception as e:
            logging.error(f"Error fetching ASN {asn}: {e}")
            return None

    @staticmethod
    async def get_bgp_updates(asn: int, hours: int = 24) -> List[Dict]:
        """Get recent BGP updates for an ASN"""
        try:
            response = requests.get(
                f"{RIPEService.BASE_URL}/bgp-updates/data.json",
                params={
                    "resource": asn,
                    "starttime": (datetime.utcnow() - timedelta(hours=hours)).isoformat()
                }
            )
            return response.json()["data"]["updates"]
        except Exception as e:
            logging.error(f"Error fetching BGP updates for ASN {asn}: {e}")
            return []

class RouteViewsService:
    """Service for interacting with RouteViews data"""
    
    @staticmethod
    async def get_as_path(source_asn: int, dest_prefix: str) -> List[List[int]]:
        """Get AS paths to a destination prefix"""
        # This would integrate with RouteViews looking glass
        # For now, returning mock data structure
        return [[source_asn, 174, 3356, dest_asn] for dest_asn in [1234, 5678]]

class BGPStreamService:
    """Service for real-time BGP stream processing using PyBGPStream"""
    
    def __init__(self):
        self.stream = pybgpstream.BGPStream(
            from_time="2024-01-01 00:00:00",
            until_time="2024-01-01 01:00:00",
            collectors=["route-views.oregon-ix", "rrc00"],
            record_type="updates"
        )
    
    def process_live_stream(self, callback):
        """Process live BGP stream and call callback for each update"""
        for rec in self.stream:
            if rec.status == "valid":
                for elem in rec:
                    bgp_update = {
                        "timestamp": elem.time,
                        "peer_asn": elem.peer_asn,
                        "prefix": elem.fields.get("prefix"),
                        "as_path": elem.fields.get("as-path", "").split(),
                        "next_hop": elem.fields.get("next-hop"),
                        "type": elem.type
                    }
                    callback(bgp_update)

# =============================================
# Threat Detection Engine
# =============================================

class ThreatDetector:
    """BGP threat detection algorithms"""
    
    def __init__(self, db: Session, redis_client):
        self.db = db
        self.redis = redis_client
    
    def detect_prefix_hijack(self, bgp_update: Dict) -> Optional[Dict]:
        """Detect potential prefix hijacking"""
        prefix = bgp_update.get("prefix")
        origin_asn = bgp_update.get("as_path", [])[-1] if bgp_update.get("as_path") else None
        
        if not prefix or not origin_asn:
            return None
        
        # Check historical origins for this prefix
        historical_key = f"prefix_origins:{prefix}"
        historical_origins = self.redis.smembers(historical_key)
        
        if historical_origins and str(origin_asn) not in historical_origins:
            return {
                "event_type": "hijack",
                "prefix": prefix,
                "origin_asn": int(origin_asn),
                "expected_origins": list(historical_origins),
                "severity": "high",
                "description": f"Prefix {prefix} announced by unexpected ASN {origin_asn}"
            }
        
        # Store this origin for future reference
        self.redis.sadd(historical_key, origin_asn)
        self.redis.expire(historical_key, 86400 * 30)  # 30 days
        
        return None
    
    def detect_route_leak(self, bgp_update: Dict) -> Optional[Dict]:
        """Detect potential route leaks"""
        as_path = bgp_update.get("as_path", [])
        
        if len(as_path) < 3:
            return None
        
        # Simple valley-free violation detection
        # In production, you'd need AS relationship data
        for i in range(1, len(as_path) - 1):
            # Check for potential valley-free violations
            # This is simplified - real implementation needs relationship data
            pass
        
        return None
    
    def calculate_threat_score(self, asn: int) -> float:
        """Calculate threat score for an ASN"""
        # Count recent threat events
        recent_threats = self.db.query(ThreatEvent).filter(
            ThreatEvent.origin_asn == asn,
            ThreatEvent.detected_at > datetime.utcnow() - timedelta(days=7)
        ).count()
        
        # Simple scoring algorithm
        base_score = min(recent_threats * 10, 100)
        return base_score

# =============================================
# Redis Setup
# =============================================

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# =============================================
# API Endpoints
# =============================================

@app.get("/api/asn/{asn}", response_model=ASNResponse)
async def get_asn_info(asn: int, db: Session = Depends(get_db)):
    """Get detailed ASN information"""
    
    # Check cache first
    cache_key = f"asn:{asn}"
    cached = redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    
    # Get from database
    asn_info = db.query(ASNInfo).filter(ASNInfo.asn == asn).first()
    
    if not asn_info:
        # Fetch from RIPE if not in database
        ripe_data = await RIPEService.get_asn_info(asn)
        if not ripe_data:
            raise HTTPException(status_code=404, detail="ASN not found")
        
        # Store in database
        asn_info = ASNInfo(
            asn=asn,
            name=ripe_data["name"],
            country=ripe_data["country"],
            org=ripe_data["org"]
        )
        db.add(asn_info)
        db.commit()
    
    # Calculate threat score
    detector = ThreatDetector(db, redis_client)
    threat_score = detector.calculate_threat_score(asn)
    
    # Determine threat level
    if threat_score >= 80:
        threat_level = "critical"
    elif threat_score >= 60:
        threat_level = "high"
    elif threat_score >= 40:
        threat_level = "medium"
    elif threat_score >= 20:
        threat_level = "low"
    else:
        threat_level = "clean"
    
    response = ASNResponse(
        asn=asn,
        name=asn_info.name,
        country=asn_info.country,
        org=asn_info.org,
        threat_score=threat_score,
        threat_level=threat_level,
        links=[]  # Would populate with BGP relationships
    )
    
    # Cache for 1 hour
    redis_client.setex(cache_key, 3600, response.json())
    
    return response

@app.get("/api/threats", response_model=List[ThreatEventResponse])
async def get_recent_threats(limit: int = 100, db: Session = Depends(get_db)):
    """Get recent threat events"""
    threats = db.query(ThreatEvent).order_by(
        ThreatEvent.detected_at.desc()
    ).limit(limit).all()
    
    return [
        ThreatEventResponse(
            id=threat.id,
            event_type=threat.event_type,
            prefix=threat.prefix,
            origin_asn=threat.origin_asn,
            severity=threat.severity,
            detected_at=threat.detected_at,
            description=threat.metadata.get("description", "")
        )
        for threat in threats
    ]

@app.get("/api/path/{source_asn}/{dest_asn}", response_model=BGPPathResponse)
async def get_as_path(source_asn: int, dest_asn: int):
    """Get AS paths between two ASNs"""
    
    # This would use RouteViews or similar service
    paths = await RouteViewsService.get_as_path(source_asn, f"{dest_asn}")
    
    return BGPPathResponse(
        source_asn=source_asn,
        dest_asn=dest_asn,
        paths=paths,
        path_analysis={
            "avg_path_length": sum(len(p) for p in paths) / len(paths) if paths else 0,
            "unique_paths": len(paths),
            "common_transit_asns": []  # Would calculate most common transit ASNs
        }
    )

@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    """WebSocket endpoint for live BGP threat feed"""
    await websocket.accept()
    
    try:
        while True:
            # In production, this would connect to real BGP stream
            # For now, send periodic mock updates
            
            mock_event = {
                "timestamp": datetime.utcnow().isoformat(),
                "type": "threat_detected",
                "data": {
                    "event_type": "hijack",
                    "prefix": "192.168.1.0/24",
                    "origin_asn": 64512,
                    "severity": "high"
                }
            }
            
            await websocket.send_text(json.dumps(mock_event))
            await asyncio.sleep(5)  # Send update every 5 seconds
            
    except Exception as e:
        logging.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()

# =============================================
# Background Tasks
# =============================================

@app.on_event("startup")
async def startup_event():
    """Initialize background tasks"""
    # Start BGP stream processing
    asyncio.create_task(process_bgp_stream())

async def process_bgp_stream():
    """Background task to process live BGP stream"""
    db = SessionLocal()
    detector = ThreatDetector(db, redis_client)
    
    def handle_bgp_update(update):
        """Handle each BGP update"""
        try:
            # Run threat detection
            hijack = detector.detect_prefix_hijack(update)
            if hijack:
                # Store threat event
                threat = ThreatEvent(
                    event_type=hijack["event_type"],
                    prefix=hijack["prefix"],
                    origin_asn=hijack["origin_asn"],
                    severity=hijack["severity"],
                    metadata=hijack
                )
                db.add(threat)
                db.commit()
                
                # Send to WebSocket clients (you'd need to manage connections)
                logging.info(f"Threat detected: {hijack}")
                
        except Exception as e:
            logging.error(f"Error processing BGP update: {e}")
    
    # In production, this would be the real BGP stream
    stream_service = BGPStreamService()
    stream_service.process_live_stream(handle_bgp_update)

# =============================================
# Dependency Injection
# =============================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =============================================
# Run the application
# =============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)