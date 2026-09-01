from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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

# FastAPI Optional Authentication Dependency (Guests allowed if header omitted; invalid/expired token returns 401)
def get_current_user_optional(authorization: str = Header(None, alias="Authorization")):
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = authorization.split(" ")[1].strip() if len(authorization.split(" ")) > 1 else ""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    user = get_current_user_from_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user

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
        "exposed_paths": {"success": False, "findings": [], "error": reason}
    }

# Scan route
@app.post("/scan")
def scan_website(data: ScanRequest, current_user: dict = Depends(get_current_user)):
    scans_left = current_user.get("scans_remaining", 0)
    if scans_left <= 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No scans remaining"
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

        def run_safe(scanner_fn, *args, default_dict=None):
            try:
                res = scanner_fn(*args)
                if isinstance(res, dict):
                    return res
                return default_dict or {"success": False, "error": "Invalid scanner return format"}
            except Exception as ex:
                print(f"Scanner exception ({scanner_fn.__name__}): {ex}")
                return default_dict or {"success": False, "error": str(ex)}

        headers_result = run_safe(scan_headers, target_url, resolved_ip, default_dict={"success": False, "headers": {}, "missing_headers": []})
        ssl_result = run_safe(scan_ssl, target_url, resolved_ip, default_dict={"success": False, "ssl_enabled": False})
        ports_result = run_safe(scan_ports, target_url, resolved_ip, default_dict={"success": False, "open_ports": [], "vulnerable_ports": [], "vulnerability_counts": {}})
        seo_result = run_safe(scan_seo, target_url, resolved_ip, default_dict={"success": False, "title": "Not Found", "h1_count": 0, "missing_alt_images": 0})
        dns_result = run_safe(scan_dns, target_url, resolved_ip, default_dict={"success": False, "ip_address": resolved_ip or "Not Found", "A": [], "MX": [], "NS": [], "TXT": []})
        technology_result = run_safe(scan_technology, target_url, resolved_ip, default_dict={"success": False, "technologies": {}})
        performance_result = run_safe(scan_performance, target_url, resolved_ip, default_dict={"success": False, "performance_score": 50})
        info_result = run_safe(scan_info, target_url, resolved_ip, default_dict={"success": False})
        cors_result = run_safe(scan_cors, target_url, resolved_ip, default_dict={"success": False, "risk_level": "LOW", "findings": []})
        exposed_paths_result = run_safe(scan_exposed_paths, target_url, resolved_ip, default_dict={"success": False, "findings": []})

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
        try:
            from database import scans_collection
            scan_doc = {
                "userId": current_user["id"],
                "email": current_user["email"],
                "url": target_url,
                "score": score_result.get("security_score", 50) if score_result else 50,
                "risk_level": score_result.get("risk_level", "UNKNOWN") if score_result else "UNKNOWN",
                "createdAt": datetime.now(timezone.utc).isoformat()
            }
            scans_collection.insert_one(scan_doc)
        except Exception as scan_err:
            print(f"Error saving scan document to MongoDB: {scan_err}")

        return {
            "success": True,
            "website": target_url,
            "summary": {
                "security_score": score_result.get("security_score", 50) if score_result else 50,
                "risk_level": score_result.get("risk_level", "UNKNOWN") if score_result else "UNKNOWN",
                "recommendations": score_result.get("recommendations", []) if score_result else [],
                "human_summary": human_summary
            },
            "website_info": info_result,
            "scans": {
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