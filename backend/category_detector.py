import re
from urllib.parse import urlparse

# High-confidence Top-Level Domains & Suffixes
DOMAIN_TLD_RULES = {
    "Government": [".gov", ".gov.in", ".gov.uk", ".gov.au", ".nic.in", ".mil"],
    "Education": [".edu", ".edu.in", ".ac.in", ".ac.uk", ".ac.nz", ".edu.au"]
}

# Category Configuration with Domain Patterns, Header Keywords, and Content Keywords
CATEGORY_CONFIG = {
    "Education": {
        "domain_patterns": [
            r"univ", r"college", r"school", r"academy", r"campus", r"sppu",
            r"iit", r"nit", r"mit", r"stanford", r"harvard", r"oxford",
            r"cambridge", r"coursera", r"udemy", r"edx", r"udacity", r"khanacademy"
        ],
        "title_keywords": [
            "university", "college", "school", "academy", "institute of technology",
            "campus", "admissions", "education", "academics", "syllabus", "courses",
            "faculty", "student portal", "curriculum"
        ],
        "body_keywords": [
            "university", "college", "school", "campus", "admission", "admissions",
            "syllabus", "curriculum", "faculty", "students", "alumni", "degree",
            "undergraduate", "postgraduate", "tuition fees", "academic calendar",
            "semester", "course catalog", "scholars"
        ]
    },
    "Hospital": {
        "domain_patterns": [
            r"hospital", r"clinic", r"healthcare", r"apollo", r"fortis", r"mayo",
            r"clevelandclinic", r"webmd", r"practo", r"1mg", r"pharma", r"aiims"
        ],
        "title_keywords": [
            "hospital", "clinic", "healthcare", "medical center", "doctor",
            "patient care", "health system", "specialty clinic",
            "medical college hospital", "multi-specialty", "medical sciences"
        ],
        "body_keywords": [
            "hospital", "clinic", "doctor", "doctors", "patient", "patients",
            "appointment", "medical care", "healthcare", "diagnosis", "treatment",
            "surgery", "emergency care", "physician", "specialist", "pharmacy",
            "cardiology", "oncology", "pediatrics", "neurology", "intensive care",
            "inpatient", "outpatient", "opd"
        ]
    },
    "Real Estate": {
        "domain_patterns": [
            r"realty", r"realestate", r"zillow", r"housing", r"magicbricks",
            r"99acres", r"realtor", r"redfin", r"trulia", r"nobroker", r"commonfloor"
        ],
        "title_keywords": [
            "real estate", "property", "properties", "apartments", "homes for sale",
            "realtor", "realty", "flats for sale", "housing", "properties for rent"
        ],
        "body_keywords": [
            "real estate", "property for sale", "properties for rent",
            "apartments for rent", "houses for sale", "buy flat", "villa for sale",
            "mortgage rates", "builder floor", "sq ft", "square feet", "realtor",
            "realty", "residential property", "commercial property",
            "property listings", "floor plan", "possession date", "rera registered"
        ]
    },
    "E-commerce": {
        "domain_patterns": [
            r"shop", r"store", r"flipkart", r"amazon", r"ebay", r"etsy",
            r"walmart", r"target", r"aliexpress", r"myntra", r"meesho",
            r"ajio", r"nykaa"
        ],
        "title_keywords": [
            "online shopping", "shop online", "store", "buy online", "ecommerce",
            "shopping cart", "marketplace", "electronics, apparel", "online store"
        ],
        "body_keywords": [
            "add to cart", "shopping cart", "checkout", "buy now", "order now",
            "free shipping", "product catalog", "products in cart",
            "proceed to checkout", "items in cart", "customer reviews",
            "return policy", "shop by category", "delivery charges",
            "cash on delivery", "add to wishlist", "coupon code"
        ]
    },
    "Government": {
        "domain_patterns": [
            r"sarkar", r"digitalindia", r"mygov", r"uidai", r"passportindia", r"incometax"
        ],
        "title_keywords": [
            "government", "ministry of", "department of", "official portal",
            "citizen services", "national portal", "republic of",
            "government of india", "state government"
        ],
        "body_keywords": [
            "ministry of", "department of", "government of", "citizen services",
            "official portal", "sarkar", "public services", "national portal",
            "e-governance", "parliament", "gazette", "statutory body",
            "municipal corporation", "public grievances", "aadhaar", "ration card"
        ]
    },
    "Corporate": {
        "domain_patterns": [
            r"consulting", r"consultancy", r"advisory", r"mckinsey", r"accenture",
            r"deloitte", r"kpmg", r"pwc", r"ey\.com", r"bain", r"tata",
            r"infosys", r"wipro", r"cognizant", r"capgemini"
        ],
        "title_keywords": [
            "management consulting", "enterprise solutions", "global consulting",
            "corporate services", "business consulting", "advisory services",
            "b2b solutions", "it consulting", "professional services"
        ],
        "body_keywords": [
            "management consulting", "enterprise solutions", "business consulting",
            "corporate governance", "b2b solutions", "strategic consulting",
            "digital transformation", "client portfolio", "global operations",
            "investor relations", "case studies", "consulting services",
            "enterprise transformation"
        ]
    }
}


def detect_category(url: str, page_title: str = "", meta_description: str = "", page_text: str = "") -> str:
    """
    High-accuracy website category detection using multi-signal scoring.
    
    Weights:
      - TLD match (.edu, .gov): 6 points
      - Domain regex pattern: 5 points
      - Page title & meta description keywords: 3-4 points each
      - Body text keywords: 1-2 points (capped per keyword to prevent spam)
      - Confidence threshold: score >= 3 (defaults to 'Other' if uncertain)
    """
    domain = ""
    try:
        if not url.startswith(("http://", "https://")):
            parsed = urlparse("https://" + url)
        else:
            parsed = urlparse(url)
        domain = (parsed.hostname or parsed.netloc or url).lower()
    except Exception:
        domain = (url or "").lower()

    domain_parts = domain.split(".")
    domain_name = domain_parts[-2] if len(domain_parts) >= 2 else domain

    title_clean = (page_title or "").lower()
    meta_clean = (meta_description or "").lower()
    header_content = f"{title_clean} {meta_clean}".strip()
    body_clean = (page_text or "").lower()

    scores = {}

    for cat, cfg in CATEGORY_CONFIG.items():
        score = 0

        # TLD score (weight = 6 points)
        for tld in DOMAIN_TLD_RULES.get(cat, []):
            if domain.endswith(tld) or f"{tld}." in domain:
                score += 6
                break

        # Domain pattern match (weight = 5 points)
        for pattern in cfg.get("domain_patterns", []):
            if re.search(pattern, domain_name):
                score += 5
                break

        # Title & Meta keywords (weight = 3-4 points)
        for t_kw in cfg.get("title_keywords", []):
            if " " in t_kw:
                if t_kw in header_content:
                    score += 4
            else:
                if re.search(rf"\b{re.escape(t_kw)}\b", header_content):
                    score += 3

        # Body text keywords (capped per keyword to avoid keyword stuffing)
        for b_kw in cfg.get("body_keywords", []):
            if " " in b_kw:
                count = body_clean.count(b_kw)
                if count > 0:
                    score += min(count * 2, 6)
            else:
                matches = len(re.findall(rf"\b{re.escape(b_kw)}\b", body_clean))
                if matches > 0:
                    score += min(matches, 3)

        if score > 0:
            scores[cat] = score

    # Minimum confidence threshold (prevents false positives)
    MIN_THRESHOLD = 3
    valid_scores = {k: v for k, v in scores.items() if v >= MIN_THRESHOLD}

    if not valid_scores:
        return "Other"

    # Return category with highest confidence score
    best_category = max(valid_scores, key=valid_scores.get)
    return best_category
