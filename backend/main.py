from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from pydantic import BaseModel, EmailStr
from database import users_collection


from scanners.technology_scanner import scan_technology
from scanners.headers_scanner import scan_headers
from scanners.ssl_scanner import scan_ssl
from scanners.port_scanner import scan_ports
from scanners.dns_scanner import scan_dns
from scanners.info_scanner import scan_info

from services.scoring_service import calculate_score
from scanners.seo_scanner import scan_seo
from scanners.performance_scanner import scan_performance
from scanners.cors_scanner import scan_cors
from scanners.exposed_paths_scanner import scan_exposed_paths
from services.ai_service import get_ai_response
from services.url_validator import validate_public_url

from services.auth_service import (
    hash_password, verify_password, create_access_token,
    get_current_user_from_token, sanitize_user, validate_password_strength
)

import os

app = FastAPI()

# Mount static files for frontend serving
from fastapi.staticfiles import StaticFiles
frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

# Environment-based CORS configuration (uses ALLOWED_ORIGINS in production, allows dev origins locally)
allowed_origins_env = os.getenv("ALLOWED_ORIGINS") or os.getenv("PRODUCTION_ORIGIN")
if allowed_origins_env:
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    # Development default: allow all origins dynamically so local testing & file:// browsing never fail CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r".*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# FastAPI Optional Authentication Dependency (Guests allowed if header omitted or invalid/expired)
def get_current_user_optional(authorization: str = Header(None, alias="Authorization")):
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1].strip() if len(authorization.split(" ")) > 1 else ""
    if not token:
        return None
    try:
        return get_current_user_from_token(token)
    except Exception:
        return None

def get_current_user(authorization: str = Header(None, alias="Authorization")):
    user = get_current_user_optional(authorization)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


# Request models
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
    summary: ScanSummary
    website_info: Optional[Dict[str, Any]] = None
    scans: Optional[ScanModules] = None
    error: Optional[str] = None

class ChatRequest(BaseModel):
    message: str
    scan_results: dict = None
    api_key: str = None
    module: str = None
    is_suggestion: bool = False

class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str | None = None
    name: str | None = None

class LoginRequest(BaseModel):
    email: str
    password: str

def process_user_registration(data: RegisterRequest):
    email = data.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address format.")

    is_valid_pwd, pwd_err = validate_password_strength(data.password)
    if not is_valid_pwd:
        raise HTTPException(status_code=400, detail=pwd_err)

    full_name = (data.full_name or data.name or "").strip()
    if not full_name:
        raise HTTPException(status_code=400, detail="Full name is required.")

    existing = users_collection.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email is already registered. Please log in.")

    pwd_hash, salt = hash_password(data.password.strip())
    created_at = datetime.now(timezone.utc).isoformat()
    user_doc = {
        "email": email,
        "password_hash": pwd_hash,
        "salt": salt,
        "full_name": full_name,
        "scans_remaining": 100,
        "created_at": created_at
    }
    result = users_collection.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id

    token = create_access_token({"sub": email})
    sanitized = sanitize_user(user_doc)

    return {
        "success": True,
        "message": "Registration successful!",
        "access_token": token,
        "token_type": "bearer",
        "user": sanitized
    }

# Home route
@app.get("/")
def home():
    return {
        "message": "Website Security Scanner API Running"
    }

# Authentication routes
@app.post("/api/auth/register")
def register_user(data: RegisterRequest):
    return process_user_registration(data)

@app.post("/api/auth/signup")
def signup_user(data: RegisterRequest):
    return process_user_registration(data)

@app.post("/api/auth/login")
def login_user(data: LoginRequest):
    email = data.email.strip().lower()
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not verify_password(data.password.strip(), user.get("password_hash", ""), user.get("salt", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_access_token({"sub": email})
    sanitized = sanitize_user(user)

    return {
        "success": True,
        "message": "Login successful!",
        "access_token": token,
        "token_type": "bearer",
        "user": sanitized
    }

@app.get("/api/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "success": True,
        "user": current_user
    }

@app.post("/api/auth/logout")
def logout_user():
    return {"success": True, "message": "Logged out successfully."}


# Chat route
@app.post("/chat")
def chat_with_advisor(data: ChatRequest, current_user: dict = Depends(get_current_user)):
    response_data = get_ai_response(data.message, data.scan_results, data.api_key, data.module, data.is_suggestion)
    return response_data


@app.get("/api/scans/history")
def get_scan_history(current_user: dict = Depends(get_current_user)):
    from database import scans_collection
    docs = list(scans_collection.find({"userId": current_user["id"]}).sort("createdAt", -1).limit(50))
    history = []
    for d in docs:
        history.append({
            "id": str(d.get("_id")),
            "url": d.get("url"),
            "score": d.get("score"),
            "risk_level": d.get("risk_level"),
            "createdAt": d.get("createdAt")
        })
    return {"success": True, "scans": history}

def generate_human_summary(website_info, score_result, ssl_result, headers_result, ports_result, performance_result):
    if not website_info or not website_info.get("success"):
        website_info = {}
        
    domain = website_info.get("registered_domain") or "the website"
    ip = website_info.get("ip_address") or "Unknown"
    country = website_info.get("country") or "Unknown"
    isp = website_info.get("isp") or "Unknown"
    registrar = website_info.get("registrar") or "Unknown"
    created = website_info.get("created") or "Unknown"

    if country != "Unknown" and isp != "Unknown":
        intro = f"This website ({domain}) is hosted on server IP {ip} in {country} and is managed by {isp}."
    else:
        intro = f"This website ({domain}) is hosted on server IP {ip}."

    if registrar != "Unknown" and created != "Unknown":
        intro += f" The domain is registered with {registrar} and was established on {created}."
    elif registrar != "Unknown":
        intro += f" The domain is registered with {registrar}."
    elif created != "Unknown":
        intro += f" The domain was established on {created}."

    score = score_result.get("security_score", 100) if score_result else 100
    risk = (score_result.get("risk_level", "LOW") if score_result else "LOW").upper()
    sec_intro = f" Our security scan rated this website's risk level as {risk} with a security score of {score}/100."

    ssl_ok = False
    if ssl_result and ssl_result.get("success"):
        ssl_ok = ssl_result.get("ssl_enabled", False)
        
    if ssl_ok:
        proto = ssl_result.get("protocol_version", "HTTPS")
        issuer = ssl_result.get("issuer", "a verified authority")
        ssl_text = f" The website is secure for standard visitors, establishing an encrypted connection using {proto} issued by {issuer}."
    else:
        ssl_text = " ⚠️ WARNING: The website does not use a secure connection (SSL is disabled or invalid). Visitors' personal information, like passwords, is exposed to potential interceptors."

    concerns = []
    if headers_result and headers_result.get("success"):
        missing_headers = len(headers_result.get("missing_headers", []))
        if missing_headers > 0:
            concerns.append(f"it is missing {missing_headers} essential security headers (which protect against cross-site attacks)")
            
    if ports_result and ports_result.get("success"):
        open_ports = ports_result.get("open_ports", [])
        if open_ports:
            port_list = [str(p["port"]) for p in open_ports]
            concerns.append(f"it has exposed services on open ports: {', '.join(port_list)}")

    if concerns:
        threat_text = " However, we detected potential safety concerns: " + " and ".join(concerns) + "."
    else:
        threat_text = " The server configuration is secure with no high-risk open ports detected."

    perf_score = 100
    load_time = "-"
    if performance_result and performance_result.get("success"):
        perf_score = performance_result.get("performance_score", 100)
        load_time = performance_result.get("first_contentful_paint", "-")
        
    if perf_score >= 80:
        perf_text = f" In terms of speed, the website is fast (Performance Score: {perf_score}/100), loading in about {load_time}."
    elif perf_score >= 50:
        perf_text = f" Performance is moderate (Performance Score: {perf_score}/100), with a load time of {load_time}."
    else:
        perf_text = f" ⚠️ Performance is slow (Performance Score: {perf_score}/100). The page takes {load_time} to render, which could frustrate visitors."

    if score >= 80:
        verdict = " Overall, this website appears highly secure and well-configured for everyday use."
    elif score >= 50:
        verdict = " Overall, the website is moderately secure, but we advise implementing the recommendations below to guard against common threats."
    else:
        verdict = " 🔴 CRITICAL: The website has significant security concerns. Administrators should address these vulnerabilities immediately to protect their users."

    return intro + sec_intro + ssl_text + threat_text + perf_text + verdict

def get_fallback_scans(reason: str = "Scan unavailable"):
    return {
        "ssl": {"success": False, "ssl_enabled": False, "error": reason},
        "headers": {"success": False, "headers": {}, "missing_headers": [], "error": reason},
        "ports": {"success": False, "open_ports": [], "vulnerable_ports": [], "vulnerability_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "error": reason},
        "seo": {"success": False, "title": "Not Found", "meta_description": None, "h1_count": 0, "missing_alt_images": 0, "error": reason},
        "dns": {"success": False, "ip_address": "Not Found", "A": [], "MX": [], "NS": [], "TXT": [], "has_spf": False, "has_dmarc": False, "error": reason},
        "performance": {"success": False, "performance_score": 0, "error": reason},
        "technology": {"success": False, "technologies": {}, "error": reason},
        "cors": {"success": False, "risk_level": "LOW", "findings": [], "error": reason},
        "exposed_paths": {"success": False, "exposed_paths": [], "total_checked": 0, "exposed_count": 0, "protected_paths": [], "error": reason}
    }

def run_safe(scanner_fn, *args, default_dict=None):
    try:
        res = scanner_fn(*args)
        if isinstance(res, dict):
            return res
        return default_dict or {"success": False, "error": "Invalid scanner return format"}
    except Exception as ex:
        print(f"Scanner exception ({scanner_fn.__name__}): {ex}")
        return default_dict or {"success": False, "error": str(ex)}

from concurrent.futures import ThreadPoolExecutor

def execute_all_scanners(target_url: str, resolved_ip: str):
    with ThreadPoolExecutor(max_workers=10) as executor:
        f_headers = executor.submit(run_safe, scan_headers, target_url, resolved_ip, default_dict={"success": False, "headers": {}, "missing_headers": []})
        f_ssl = executor.submit(run_safe, scan_ssl, target_url, resolved_ip, default_dict={"success": False, "ssl_enabled": False})
        f_ports = executor.submit(run_safe, scan_ports, target_url, resolved_ip, default_dict={"success": False, "open_ports": [], "vulnerable_ports": [], "vulnerability_counts": {}})
        f_seo = executor.submit(run_safe, scan_seo, target_url, resolved_ip, default_dict={"success": False, "title": "Not Found", "h1_count": 0, "missing_alt_images": 0})
        f_dns = executor.submit(run_safe, scan_dns, target_url, resolved_ip, default_dict={"success": False, "ip_address": resolved_ip or "Not Found", "A": [], "MX": [], "NS": [], "TXT": []})
        f_tech = executor.submit(run_safe, scan_technology, target_url, resolved_ip, default_dict={"success": False, "technologies": {}})
        f_perf = executor.submit(run_safe, scan_performance, target_url, resolved_ip, default_dict={"success": False, "performance_score": 50})
        f_info = executor.submit(run_safe, scan_info, target_url, resolved_ip, default_dict={"success": False})
        f_cors = executor.submit(run_safe, scan_cors, target_url, resolved_ip, default_dict={"success": False, "risk_level": "LOW", "findings": []})
        f_exposed = executor.submit(run_safe, scan_exposed_paths, target_url, resolved_ip, default_dict={"success": False, "exposed_paths": [], "total_checked": 0, "exposed_count": 0, "protected_paths": []})

        headers_result = f_headers.result()
        ssl_result = f_ssl.result()
        ports_result = f_ports.result()
        seo_result = f_seo.result()
        dns_result = f_dns.result()
        technology_result = f_tech.result()
        performance_result = f_perf.result()
        info_result = f_info.result()
        cors_result = f_cors.result()
        exposed_paths_result = f_exposed.result()

    return {
        "headers": headers_result,
        "ssl": ssl_result,
        "ports": ports_result,
        "seo": seo_result,
        "dns": dns_result,
        "technology": technology_result,
        "performance": performance_result,
        "info": info_result,
        "cors": cors_result,
        "exposed_paths": exposed_paths_result
    }

# Scan route
@app.post("/scan", response_model=ScanResponse)
def scan_website(data: ScanRequest, current_user: dict = Depends(get_current_user_optional)):
    if current_user:
        scans_left = current_user.get("scans_remaining", 0)
        if scans_left <= 0:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No scans remaining. Please upgrade your account."
            )

        users_collection.update_one(
            {"email": current_user["email"]},
            {"$inc": {"scans_remaining": -1}}
        )
    try:
        # Normalize and clean input URL
        target_url = data.url.strip().replace(" ", "")
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "https://" + target_url

        print(f"Initiating scan for target: {target_url}")

        # Validate target host before running any scanners to prevent SSRF
        is_valid, resolved_ip, reason = validate_public_url(target_url)
        if not is_valid:
            print(f"SSRF validation blocked target {target_url}: {reason}. Skipping all scanners.")
            return {
                "success": False,
                "website": data.url,
                "error": reason,
                "summary": {
                    "security_score": 0,
                    "risk_level": "UNKNOWN",
                    "recommendations": ["Scan failed to complete because the target host is not valid or not accessible."],
                    "human_summary": f"An error occurred while scanning {data.url}: {reason}"
                },
                "website_info": {},
                "scans": get_fallback_scans(reason)
            }

        full_scans_dict = execute_all_scanners(target_url, resolved_ip)
        headers_result = full_scans_dict["headers"]
        ssl_result = full_scans_dict["ssl"]
        ports_result = full_scans_dict["ports"]
        seo_result = full_scans_dict["seo"]
        dns_result = full_scans_dict["dns"]
        technology_result = full_scans_dict["technology"]
        performance_result = full_scans_dict["performance"]
        info_result = full_scans_dict["info"]
        cors_result = full_scans_dict["cors"]
        exposed_paths_result = full_scans_dict["exposed_paths"]

        score_result = calculate_score(
            headers_result,
            ssl_result,
            ports_result,
            seo_result,
            performance_result,
            dns_result,
            cors_result,
            exposed_paths=exposed_paths_result
        )

        human_summary = generate_human_summary(
            info_result,
            score_result,
            ssl_result,
            headers_result,
            ports_result,
            performance_result
        )

        # Save scan document into scans_collection in MongoDB Atlas
        scan_id_str = None
        full_scans_dict = {
            "ssl": ssl_result,
            "headers": headers_result,
            "ports": ports_result,
            "seo": seo_result,
            "dns": dns_result,
            "performance": performance_result,
            "technology": technology_result,
            "cors": cors_result,
            "exposed_paths": exposed_paths_result
        }
        summary_dict = {
            "security_score": score_result.get("security_score", 50) if score_result else 50,
            "risk_level": score_result.get("risk_level", "UNKNOWN") if score_result else "UNKNOWN",
            "recommendations": score_result.get("recommendations", []) if score_result else [],
            "human_summary": human_summary
        }
        try:
            from database import scans_collection
            scan_doc = {
                "userId": current_user["id"] if current_user else None,
                "email": current_user["email"] if current_user else "guest@shieldscope.local",
                "url": target_url,
                "score": score_result.get("security_score", 50) if score_result else 50,
                "risk_level": score_result.get("risk_level", "UNKNOWN") if score_result else "UNKNOWN",
                "createdAt": datetime.now(timezone.utc).isoformat(),
                "summary": summary_dict,
                "website_info": info_result,
                "scans": full_scans_dict
            }
            res = scans_collection.insert_one(scan_doc)
            scan_id_str = str(res.inserted_id)
        except Exception as scan_err:
            print(f"Error saving scan document to MongoDB: {scan_err}")


        return {
            "id": scan_id_str,
            "success": True,
            "website": target_url,
            "summary": summary_dict,
            "website_info": info_result,
            "scans": full_scans_dict
        }
    except Exception as e:
        print(f"Error executing scan: {e}")
        return {
            "success": False,
            "website": data.url,
            "error": str(e),
            "summary": {
                "security_score": 0,
                "risk_level": "UNKNOWN",
                "recommendations": ["Scan failed to complete due to an unexpected error."],
                "human_summary": f"An error occurred while scanning {data.url}: {str(e)}"
            },
            "website_info": {},
            "scans": get_fallback_scans(str(e))
        }


# PDF Generation Helper
def generate_pdf_report_bytes(scan_data: dict) -> bytes:
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        fontName='Helvetica-Bold'
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b')
    )
    heading2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1e293b'),
        fontName='Helvetica-Bold',
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    story = []

    url = scan_data.get('url') or scan_data.get('website') or 'Target Website'
    score = scan_data.get('score') if scan_data.get('score') is not None else scan_data.get('summary', {}).get('security_score', 0)
    risk = str(scan_data.get('risk_level') or scan_data.get('summary', {}).get('risk_level', 'UNKNOWN')).upper()
    date_str = scan_data.get('createdAt') or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story.append(Paragraph("ShieldScope - Security Audit Report", title_style))
    story.append(Paragraph(f"Target URL: <b>{url}</b> &nbsp;|&nbsp; Audit Date: {date_str}", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=12))

    score_bg = colors.HexColor('#dcfce7') if score >= 80 else (colors.HexColor('#fef9c3') if score >= 50 else colors.HexColor('#fee2e2'))
    score_hex = '#166534' if score >= 80 else ('#854d0e' if score >= 50 else '#991b1b')

    score_data = [
        [
            Paragraph(f"<b>Overall Security Score</b><br/><font size=18 color='{score_hex}'><b>{score} / 100</b></font>", body_style),
            Paragraph(f"<b>Risk Rating</b><br/><font size=15 color='{score_hex}'><b>{risk}</b></font>", body_style)
        ]
    ]
    score_table = Table(score_data, colWidths=[270, 270])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), score_bg),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 10),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#94a3b8'))
    ]))
    story.append(score_table)
    story.append(Spacer(1, 12))

    human_sum = scan_data.get('summary', {}).get('human_summary')
    if human_sum:
        story.append(Paragraph("Executive Summary", heading2_style))
        story.append(Paragraph(human_sum, body_style))
        story.append(Spacer(1, 10))

    story.append(Paragraph("Scanner Modules Assessment", heading2_style))
    module_rows = [
        [Paragraph("<b>Security Module</b>", body_style), Paragraph("<b>Status & Findings</b>", body_style)]
    ]

    scans = scan_data.get('scans', {})

    # SSL
    ssl_info = scans.get('ssl', {})
    ssl_status = "Secure (HTTPS)" if ssl_info.get('ssl_enabled') else "Insecure / Invalid SSL"
    module_rows.append([Paragraph("SSL / TLS Certificate", body_style), Paragraph(ssl_status, body_style)])

    # Headers
    headers_info = scans.get('headers', {})
    missing_h = len(headers_info.get('missing_headers', []))
    h_desc = f"Missing {missing_h} security header(s)" if missing_h > 0 else "All key security headers present"
    module_rows.append([Paragraph("Security Headers", body_style), Paragraph(h_desc, body_style)])

    # Ports
    ports_info = scans.get('ports', {})
    open_p = len(ports_info.get('open_ports', []))
    p_desc = f"{open_p} open port(s) detected" if open_p > 0 else "No risky open ports detected"
    module_rows.append([Paragraph("Port & Service Scanner", body_style), Paragraph(p_desc, body_style)])

    # DNS
    dns_info = scans.get('dns', {})
    spf = "SPF Configured" if dns_info.get('has_spf') else "Missing SPF"
    dmarc = "DMARC Configured" if dns_info.get('has_dmarc') else "Missing DMARC"
    module_rows.append([Paragraph("DNS Configuration", body_style), Paragraph(f"IP: {dns_info.get('ip_address', 'N/A')} | {spf} | {dmarc}", body_style)])

    # Performance
    perf_info = scans.get('performance', {})
    perf_score = perf_info.get('performance_score', 'N/A')
    module_rows.append([Paragraph("Performance Analysis", body_style), Paragraph(f"Score: {perf_score}/100 | FCP: {perf_info.get('first_contentful_paint', 'N/A')}", body_style)])

    # SEO
    seo_info = scans.get('seo', {})
    module_rows.append([Paragraph("SEO & Structure Audit", body_style), Paragraph(f"Title: {seo_info.get('title', 'N/A')} | H1 Tags: {seo_info.get('h1_count', 0)}", body_style)])

    # CORS
    cors_info = scans.get('cors', {})
    module_rows.append([Paragraph("CORS Policy", body_style), Paragraph(f"Risk Level: {cors_info.get('risk_level', 'LOW')}", body_style)])

    # Exposed Paths
    exp_info = scans.get('exposed_paths', {})
    found_paths = len(exp_info.get('exposed_paths', []))
    module_rows.append([Paragraph("Exposed Sensitive Files", body_style), Paragraph(f"{found_paths} sensitive file/path finding(s)", body_style)])

    # Tech Stack
    tech_info = scans.get('technology', {})
    tech_list = list(tech_info.get('technologies', {}).keys())
    t_desc = ", ".join(tech_list[:5]) if tech_list else "No specific server header exposed"
    module_rows.append([Paragraph("Technology Stack", body_style), Paragraph(t_desc, body_style)])

    mod_table = Table(module_rows, colWidths=[180, 360])
    mod_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
    ]))
    story.append(mod_table)
    story.append(Spacer(1, 12))

    recs = scan_data.get('summary', {}).get('recommendations', [])
    if recs:
        story.append(Paragraph("Remediation Action Items", heading2_style))
        for r in recs:
            story.append(Paragraph(f"• {r}", body_style))
            story.append(Spacer(1, 2))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


# Single Scan Detail Endpoint
@app.get("/api/scans/{scan_id}")
def get_scan_detail(scan_id: str, current_user: dict = Depends(get_current_user)):
    from database import scans_collection
    from bson import ObjectId
    try:
        doc = scans_collection.find_one({"_id": ObjectId(scan_id), "userId": current_user["id"]})
        if not doc:
            raise HTTPException(status_code=404, detail="Scan not found")
        doc["id"] = str(doc["_id"])
        del doc["_id"]
        return {"success": True, "scan": doc}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid scan ID")


# PDF Download Route
from fastapi import Response

@app.get("/api/scans/{scan_id}/pdf")
def download_scan_pdf(scan_id: str, current_user: dict = Depends(get_current_user)):
    from database import scans_collection
    from bson import ObjectId
    try:
        doc = scans_collection.find_one({"_id": ObjectId(scan_id), "userId": current_user["id"]})
        if not doc:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        doc["id"] = str(doc["_id"])
        pdf_bytes = generate_pdf_report_bytes(doc)
        filename = f"ShieldScope_Report_{doc.get('url', 'scan').replace('https://','').replace('http://','').replace('/','_')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not generate PDF: {str(e)}")


# Scheduled Scans Models and Endpoints
class ScheduleRequest(BaseModel):
    url: str
    frequency: str = "weekly" # "daily" or "weekly"

@app.get("/api/scans/schedule")
def get_scheduled_scan(current_user: dict = Depends(get_current_user)):
    from database import scheduled_scans_collection
    sched = scheduled_scans_collection.find_one({"userId": current_user["id"]})
    if not sched:
        return {"success": True, "scheduled": False, "schedule": None}
    sched["id"] = str(sched["_id"])
    del sched["_id"]
    return {"success": True, "scheduled": True, "schedule": sched}

@app.post("/api/scans/schedule")
def create_scheduled_scan(data: ScheduleRequest, current_user: dict = Depends(get_current_user)):
    from database import scheduled_scans_collection
    target_url = data.url.strip()
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    is_valid, resolved_ip, reason = validate_public_url(target_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Target URL invalid: {reason}")

    next_run = (datetime.now(timezone.utc) + (timedelta(days=1) if data.frequency == "daily" else timedelta(days=7))).isoformat()
    
    doc = {
        "userId": current_user["id"],
        "email": current_user["email"],
        "url": target_url,
        "frequency": data.frequency,
        "next_run": next_run,
        "createdAt": datetime.now(timezone.utc).isoformat()
    }

    scheduled_scans_collection.update_one(
        {"userId": current_user["id"]},
        {"$set": doc},
        upsert=True
    )
    return {"success": True, "message": "Recurring scan scheduled successfully", "schedule": doc}

@app.delete("/api/scans/schedule")
def cancel_scheduled_scan(current_user: dict = Depends(get_current_user)):
    from database import scheduled_scans_collection
    scheduled_scans_collection.delete_one({"userId": current_user["id"]})
    return {"success": True, "message": "Scheduled scan cancelled"}


# Background Scheduler Setup
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import timedelta

scheduler = BackgroundScheduler()

def run_scheduled_jobs():
    try:
        from database import scheduled_scans_collection, scans_collection, users_collection
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        
        schedules = list(scheduled_scans_collection.find({}))
        for s in schedules:
            try:
                next_run_str = s.get("next_run")
                if next_run_str and datetime.fromisoformat(next_run_str) > now_dt:
                    continue
                
                target_url = s.get("url")
                user_id = s.get("userId")

                is_valid, resolved_ip, reason = validate_public_url(target_url)
                if not is_valid:
                    print(f"[Scheduler] SSRF validation failed for scheduled target {target_url}: {reason}")
                    continue

                full_scans_dict = execute_all_scanners(target_url, resolved_ip)
                headers_result = full_scans_dict["headers"]
                ssl_result = full_scans_dict["ssl"]
                ports_result = full_scans_dict["ports"]
                seo_result = full_scans_dict["seo"]
                dns_result = full_scans_dict["dns"]
                technology_result = full_scans_dict["technology"]
                performance_result = full_scans_dict["performance"]
                info_result = full_scans_dict["info"]
                cors_result = full_scans_dict["cors"]
                exposed_paths_result = full_scans_dict["exposed_paths"]

                score_result = calculate_score(
                    headers_result, ssl_result, ports_result, seo_result, performance_result, dns_result, cors_result, exposed_paths=exposed_paths_result
                )
                human_summary = generate_human_summary(
                    info_result, score_result, ssl_result, headers_result, ports_result, performance_result
                )

                freq = s.get("frequency", "weekly")
                next_dt = now_dt + (timedelta(days=1) if freq == "daily" else timedelta(days=7))

                scan_doc = {
                    "userId": user_id,
                    "email": s.get("email"),
                    "url": target_url,
                    "score": score_result.get("security_score", 50) if score_result else 50,
                    "risk_level": score_result.get("risk_level", "UNKNOWN") if score_result else "UNKNOWN",
                    "createdAt": now_iso,
                    "is_scheduled": True,
                    "summary": {
                        "security_score": score_result.get("security_score", 50) if score_result else 50,
                        "risk_level": score_result.get("risk_level", "UNKNOWN") if score_result else "UNKNOWN",
                        "recommendations": score_result.get("recommendations", []) if score_result else [],
                        "human_summary": human_summary
                    },
                    "website_info": info_result,
                    "scans": full_scans_dict
                }
                scans_collection.insert_one(scan_doc)

                scheduled_scans_collection.update_one(
                    {"_id": s["_id"]},
                    {"$set": {"next_run": next_dt.isoformat(), "last_run": now_iso}}
                )
                print(f"[Scheduler] Completed scheduled scan for {target_url} (User: {user_id})")
            except Exception as ex:
                print(f"[Scheduler] Error processing scheduled scan for {s}: {ex}")
    except Exception as outer_ex:
        print(f"[Scheduler] Background scheduler loop error: {outer_ex}")


@app.on_event("startup")
def start_background_jobs():
    try:
        scheduler.add_job(run_scheduled_jobs, 'interval', minutes=10, id='scheduled_scans_task', replace_existing=True)
        scheduler.start()
        print("Background APScheduler started successfully.")
    except Exception as e:
        print(f"Error starting BackgroundScheduler: {e}")