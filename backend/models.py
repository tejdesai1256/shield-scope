from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr


class ScanRequest(BaseModel):
    url: str


class ScanSummary(BaseModel):
    security_score: int
    risk_level: str
    recommendations: List[str] = []
    human_summary: Optional[str] = None


class ScanModules(BaseModel):
    ssl: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, Any]] = None
    ports: Optional[Dict[str, Any]] = None
    seo: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    performance: Optional[Dict[str, Any]] = None
    technology: Optional[Dict[str, Any]] = None
    cors: Optional[Dict[str, Any]] = None
    exposed_paths: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    id: Optional[str] = None
    success: bool
    website: str
    category: str = "Other"
    summary: ScanSummary
    website_info: Optional[Dict[str, Any]] = None
    scans: Optional[ScanModules] = None
    error: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    scan_results: Optional[dict] = None
    api_key: Optional[str] = None
    module: Optional[str] = None
    is_suggestion: bool = False


class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class ScheduleRequest(BaseModel):
    url: str
    frequency: str = "weekly"
