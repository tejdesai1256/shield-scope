import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

# High-confidence Top-Level Domains & Suffixes
DOMAIN_TLD_RULES = {
    "Government": [".gov", ".gov.in", ".gov.uk", ".gov.au", ".gov.ca", ".nic.in", ".mil", ".mil.in", ".fed.us"],
    "Education": [".edu", ".edu.in", ".ac.in", ".ac.uk", ".ac.nz", ".edu.au", ".ac.jp", ".school", ".academy", ".college", ".university"],
    "Hospital": [".health", ".clinic", ".hospital", ".care", ".dental", ".pharmacy", ".med"],
    "Banking & Finance": [".bank", ".fin", ".fund", ".capital", ".finance", ".financial", ".credit", ".insure", ".broker"],
    "E-commerce": [".shop", ".store", ".shopping", ".boutique", ".deals", ".fashion", ".market"],
    "Technology & SaaS": [".tech", ".dev", ".io", ".ai", ".app", ".cloud", ".software", ".systems", ".security"],
    "News & Media": [".news", ".media", ".press", ".journal", ".buzz"],
    "Real Estate": [".realty", ".estate", ".properties", ".rentals", ".house", ".apartments", ".villas"],
    "Travel & Hospitality": [".travel", ".hotel", ".flights", ".vacations", ".tours", ".cruises", ".guide"],
    "Non-Profit & NGO": [".org", ".ngo", ".foundation", ".charity", ".gives", ".relief"]
}

# Category Configuration with Domain Patterns, Header Keywords, Content Keywords, and Sector Metadata
CATEGORY_CONFIG = {
    "Education": {
        "icon": "🎓",
        "industry": "Education & EdTech",
        "description": "Academic institutions, universities, schools, learning portals, and online course providers.",
        "compliance_frameworks": ["FERPA", "COPPA", "GDPR-K", "ISO 27001"],
        "security_priorities": ["Student PII Protection", "LMS Authentication Hardening", "Anti-Phishing", "DDoS Mitigation during Exam/Admission Periods"],
        "threat_vectors": ["Credential Stuffing on Student Portals", "Ransomware on Academic Networks", "Data Leaks of Research Data"],
        "domain_patterns": [
            r"univ", r"college", r"school", r"academy", r"campus", r"sppu",
            r"iit", r"nit", r"mit", r"stanford", r"harvard", r"oxford",
            r"cambridge", r"coursera", r"udemy", r"edx", r"udacity", r"khanacademy",
            r"blackboard", r"canvas", r"moodle", r"duolingo", r"quizlet", r"chegg",
            r"byjus", r"unacademy", r"geeksforgeeks", r"leetcode", r"codecademy",
            r"alison", r"pluralsight", r"skillshare", r"edutech", r"k12"
        ],
        "title_keywords": [
            "university", "college", "school", "academy", "institute of technology",
            "campus", "admissions", "education", "academics", "syllabus", "courses",
            "faculty", "student portal", "curriculum", "learning management system",
            "online degrees", "academic calendar", "higher education", "k-12 learning"
        ],
        "body_keywords": [
            "university", "college", "school", "campus", "admission", "admissions",
            "syllabus", "curriculum", "faculty", "students", "alumni", "degree",
            "undergraduate", "postgraduate", "tuition fees", "academic calendar",
            "semester", "course catalog", "scholars", "doctoral program", "enrollment",
            "professors", "departments", "scholarships", "accredited program"
        ]
    },
    "Hospital": {
        "icon": "🏥",
        "industry": "Healthcare & Life Sciences",
        "description": "Hospitals, medical centers, clinical diagnostic labs, telehealth, and pharmaceutical platforms.",
        "compliance_frameworks": ["HIPAA", "HITECH", "DISHA (India)", "GDPR (Health Data)", "FDA Title 21 CFR Part 11"],
        "security_priorities": ["Electronic Health Record (EHR) Encryption", "Strict Access Control & MFA", "API Security for Telehealth", "Medical IoT Isolation"],
        "threat_vectors": ["Ransomware on Critical Patient Care Systems", "Medical Record Theft & Identity Fraud", "Unencrypted Telehealth Streams"],
        "domain_patterns": [
            r"hospital", r"clinic", r"healthcare", r"apollo", r"fortis", r"mayo",
            r"clevelandclinic", r"webmd", r"practo", r"1mg", r"pharma", r"aiims",
            r"maxhealthcare", r"manipal", r"medanta", r"narayana", r"nih\.gov",
            r"healthline", r"healthifyme", r"pharmasy", r"netmeds", r"medplus",
            r"doctor", r"diagnostic", r"pathology", r"telehealth", r"telemedicine"
        ],
        "title_keywords": [
            "hospital", "clinic", "healthcare", "medical center", "doctor",
            "patient care", "health system", "specialty clinic",
            "medical college hospital", "multi-specialty", "medical sciences",
            "telehealth", "find a doctor", "book appointment", "clinical care"
        ],
        "body_keywords": [
            "hospital", "clinic", "doctor", "doctors", "patient", "patients",
            "appointment", "medical care", "healthcare", "diagnosis", "treatment",
            "surgery", "emergency care", "physician", "specialist", "pharmacy",
            "cardiology", "oncology", "pediatrics", "neurology", "intensive care",
            "inpatient", "outpatient", "opd", "pathology", "diagnostic tests",
            "icu", "mri scan", "ct scan", "health checkup", "medical history"
        ]
    },
    "Banking & Finance": {
        "icon": "💳",
        "industry": "Banking, Finance & Fintech",
        "description": "Commercial & retail banks, fintech apps, payment gateways, credit unions, and investment brokers.",
        "compliance_frameworks": ["PCI-DSS v4.0", "SOC 2 Type II", "GLBA", "RBI Cyber Security Framework", "ISO 27001", "PSD2"],
        "security_priorities": ["HSTS Preload & Strict TLS 1.3", "Anti-CSRF & Strong MFA", "Subdomain Takeover Prevention", "WAF & Bot Mitigation for Financial Fraud"],
        "threat_vectors": ["Credential Stuffing & ATO (Account Takeover)", "Payment Gateway Interception", "Wire Fraud / Phishing", "API BOLA / IDOR Exploits"],
        "domain_patterns": [
            r"bank", r"chase", r"hdfc", r"icici", r"sbi", r"wellsfargo", r"citi",
            r"barclays", r"hsbc", r"revolut", r"stripe", r"paypal", r"razorpay",
            r"zerodha", r"groww", r"robinhood", r"coinbase", r"binance", r"paytm",
            r"phonepe", r"mastercard", r"visa", r"fidelity", r"vanguard", r"schwab",
            r"axisbank", r"kotak", r"capitalone", r"americannexpress", r"fintech"
        ],
        "title_keywords": [
            "banking", "online banking", "personal banking", "credit card", "debit card",
            "loan", "mortgage", "savings account", "current account", "fixed deposit",
            "wealth management", "investments", "stock trading", "payment gateway",
            "fintech", "insurance", "mutual funds", "net banking", "mobile banking"
        ],
        "body_keywords": [
            "online banking", "net banking", "savings account", "checking account",
            "credit score", "interest rate", "fixed deposit", "mutual funds",
            "home loan", "personal loan", "car loan", "money transfer", "upi",
            "swift code", "ifsc code", "routing number", "cardholder", "atm locator",
            "investment portfolio", "demat account", "kyc verification", "financial advisor"
        ]
    },
    "E-commerce": {
        "icon": "🛒",
        "industry": "E-Commerce & Retail",
        "description": "Online shopping storefronts, multi-vendor marketplaces, digital merchandise, and retail portals.",
        "compliance_frameworks": ["PCI-DSS", "GDPR", "CCPA / CPRA", "Consumer Protection Regulations"],
        "security_priorities": ["Payment Page Integrity & CSP (Anti-Magecart)", "Account Takeover Mitigation", "Rate Limiting on Checkout APIs", "Secure Cookie Flags"],
        "threat_vectors": ["Magecart / Digital Skimming", "Credential Stuffing & Loyalty Point Theft", "Price Manipulation & Cart Tampering", "Inventory Scraping & Scalper Bots"],
        "domain_patterns": [
            r"shop", r"store", r"flipkart", r"amazon", r"ebay", r"etsy",
            r"walmart", r"target", r"aliexpress", r"myntra", r"meesho",
            r"ajio", r"nykaa", r"shopify", r"bigcommerce", r"woocommerce",
            r"bestbuy", r"costco", r"asos", r"zalando", r"shein", r"zara",
            r"hm\.com", r"ikea", r"cart", r"retail", r"boutique", r"mall"
        ],
        "title_keywords": [
            "online shopping", "shop online", "store", "buy online", "ecommerce",
            "shopping cart", "marketplace", "electronics, apparel", "online store",
            "free shipping", "fashion store", "deals & discounts", "retail store"
        ],
        "body_keywords": [
            "add to cart", "shopping cart", "checkout", "buy now", "order now",
            "free shipping", "product catalog", "products in cart",
            "proceed to checkout", "items in cart", "customer reviews",
            "return policy", "shop by category", "delivery charges",
            "cash on delivery", "add to wishlist", "coupon code", "discount code",
            "track order", "fast delivery", "in stock", "out of stock", "price drop"
        ]
    },
    "News & Media": {
        "icon": "📰",
        "industry": "News, Media & Publishing",
        "description": "Journalism outlets, newspaper publications, breaking news portals, digital magazines, and broadcast networks.",
        "compliance_frameworks": ["GDPR", "CCPA", "DMCA / Copyright Protections", "Journalistic Shield & Whistleblower Data Laws"],
        "security_priorities": ["CMS Hardening (WordPress, Drupal)", "Content Integrity & Anti-Defacement", "DDoS Resilience during Breaking News", "Third-Party Ad Network Isolation"],
        "threat_vectors": ["Site Defacement & Disinformation Injections", "Malvertising from Compromised Ad Networks", "DDoS Attacks Censoring Reports", "CMS Vulnerability Exploits"],
        "domain_patterns": [
            r"nytimes", r"cnn", r"bbc", r"reuters", r"bloomberg", r"theverge",
            r"techcrunch", r"buzzfeed", r"forbes", r"wsj", r"ndtv", r"indiatimes",
            r"thehindu", r"indianexpress", r"washingtonpost", r"guardian", r"aljazeera",
            r"foxnews", r"nbcnews", r"huffpost", r"time\.com", r"news18", r"hindustantimes",
            r"latimes", r"usatoday", r"telegraph", r"dailymail", r"wired", r"economist"
        ],
        "title_keywords": [
            "breaking news", "latest news", "world news", "daily news", "journalism",
            "headlines", "press release", "editorial", "opinion column", "live updates",
            "national news", "politics", "financial news", "investigative reports"
        ],
        "body_keywords": [
            "breaking news", "read full story", "latest updates", "journalist",
            "reporter", "press club", "editorial team", "opinion", "world news",
            "politics", "live coverage", "published on", "updated at", "investigative report",
            "columnist", "news wire", "front page", "eyewitness", "exclusive report"
        ]
    },
    "Technology & SaaS": {
        "icon": "💻",
        "industry": "Technology, Cloud & SaaS",
        "description": "Software products, cloud infrastructure providers, developer tooling platforms, AI applications, and APIs.",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001", "ISO 27017 / 27018", "FedRAMP", "GDPR", "CCPA"],
        "security_priorities": ["API Gateway & Token Auth Hardening", "Strict Content-Security-Policy", "Zero-Trust Architecture", "CORS Policy Restriction & CSRF Defense"],
        "threat_vectors": ["API Key Leaks & Unauthorized Scraping", "Supply Chain / Dependency Compromise", "Server-Side Request Forgery (SSRF)", "Session Hijacking / OAuth Abuse"],
        "domain_patterns": [
            r"github", r"gitlab", r"atlassian", r"slack", r"notion", r"vercel",
            r"aws", r"azure", r"cloudflare", r"salesforce", r"docker", r"kubernetes",
            r"hashicorp", r"datadog", r"sentry", r"supabase", r"mongodb", r"digitalocean",
            r"heroku", r"postman", r"figma", r"openai", r"anthropic", r"jira", r"linear",
            r"snowflake", r"databricks", r"twilio", r"segment", r"hubspot", r"zoom"
        ],
        "title_keywords": [
            "software", "saas platform", "cloud platform", "developer tools", "api documentation",
            "open source", "devops", "sdk", "workflow automation", "enterprise software",
            "artificial intelligence", "machine learning", "cybersecurity platform", "data analytics"
        ],
        "body_keywords": [
            "api documentation", "developer docs", "sdk", "cloud infrastructure",
            "continuous integration", "open source", "rest api", "graphql", "webhooks",
            "sign up free", "start free trial", "pricing plans", "enterprise tier",
            "system uptime", "command line", "deployment", "github repository", "integrations"
        ]
    },
    "Government": {
        "icon": "🏛️",
        "industry": "Government & Public Sector",
        "description": "National, federal, state, and municipal government portals, public services, and regulatory bodies.",
        "compliance_frameworks": ["FedRAMP", "FISMA", "NIST SP 800-53", "Indian Cyber Security Directives (CERT-In)", "GDPR Public Sector"],
        "security_priorities": ["State-Sponsored Threat Defenses", "Citizen PII Safeguarding", "Strict DNSSEC & CAA Records", "High-Availability Infrastructure"],
        "threat_vectors": ["Advanced Persistent Threats (APTs)", "Mass Citizen Data Exfiltration", "Ransomware on Public Utilities", "Defacement of National Identity"],
        "domain_patterns": [
            r"sarkar", r"digitalindia", r"mygov", r"uidai", r"passportindia", r"incometax",
            r"epfindia", r"nvsp", r"parivahan", r"gst\.gov", r"irctc", r"pib\.gov",
            r"usa\.gov", r"irs\.gov", r"cdc\.gov", r"nasa\.gov", r"gov\.uk", r"canada\.ca"
        ],
        "title_keywords": [
            "government", "ministry of", "department of", "official portal",
            "citizen services", "national portal", "republic of",
            "government of india", "state government", "public administration",
            "federal government", "official government website"
        ],
        "body_keywords": [
            "ministry of", "department of", "government of", "citizen services",
            "official portal", "sarkar", "public services", "national portal",
            "e-governance", "parliament", "gazette", "statutory body",
            "municipal corporation", "public grievances", "aadhaar", "ration card",
            "public sector undertaking", "voter id", "passport services", "income tax filing"
        ]
    },
    "Real Estate": {
        "icon": "🏠",
        "industry": "Real Estate & Housing",
        "description": "Property listing aggregators, housing brokers, commercial real estate developers, and rental platforms.",
        "compliance_frameworks": ["RERA (India)", "Fair Housing Act (US)", "GDPR / Financial Lead Privacy"],
        "security_priorities": ["Lead Contact PII Protection", "Form Spam & Injection Defense", "Preventing Broker Impersonation Scams"],
        "threat_vectors": ["Lead Generation Data Scraping", "Mortgage Wire Transfer Fraud", "Fake Listing Injections"],
        "domain_patterns": [
            r"realty", r"realestate", r"zillow", r"housing", r"magicbricks",
            r"99acres", r"realtor", r"redfin", r"trulia", r"nobroker", r"commonfloor",
            r"squareyards", r"compass", r"rightmove", r"zoopla", r"century21", r"proptiger"
        ],
        "title_keywords": [
            "real estate", "property", "properties", "apartments", "homes for sale",
            "realtor", "realty", "flats for sale", "housing", "properties for rent",
            "commercial spaces", "luxury villas", "new residential projects"
        ],
        "body_keywords": [
            "real estate", "property for sale", "properties for rent",
            "apartments for rent", "houses for sale", "buy flat", "villa for sale",
            "mortgage rates", "builder floor", "sq ft", "square feet", "realtor",
            "realty", "residential property", "commercial property",
            "property listings", "floor plan", "possession date", "rera registered",
            "carpet area", "gated community", "ready to move", "under construction"
        ]
    },
    "Corporate": {
        "icon": "🏢",
        "industry": "Corporate & Enterprise Services",
        "description": "Management consultancies, B2B enterprise firms, multinational conglomerates, and agency partners.",
        "compliance_frameworks": ["ISO 27001", "SOC 2", "SOX (Sarbanes-Oxley)", "GDPR"],
        "security_priorities": ["Executive Phishing & BEC Defense", "Enterprise Identity Federation (SSO/SAML)", "Corporate Secret Protection"],
        "threat_vectors": ["Business Email Compromise (BEC)", "Corporate Espionage & IP Theft", "Third-Party Vendor Risk"],
        "domain_patterns": [
            r"consulting", r"consultancy", r"advisory", r"mckinsey", r"accenture",
            r"deloitte", r"kpmg", r"pwc", r"ey\.com", r"bain", r"tata",
            r"infosys", r"wipro", r"cognizant", r"capgemini", r"bcs", r"kroll",
            r"bostonconsulting", r"gartner", r"boozallen", r"oliverwyman", r"corp"
        ],
        "title_keywords": [
            "management consulting", "enterprise solutions", "global consulting",
            "corporate services", "business consulting", "advisory services",
            "b2b solutions", "it consulting", "professional services", "strategic advisory"
        ],
        "body_keywords": [
            "management consulting", "enterprise solutions", "business consulting",
            "corporate governance", "b2b solutions", "strategic consulting",
            "digital transformation", "client portfolio", "global operations",
            "investor relations", "case studies", "consulting services",
            "enterprise transformation", "annual report", "shareholder value", "sustainability report"
        ]
    },
    "Social Media & Community": {
        "icon": "👥",
        "industry": "Social Media & Community",
        "description": "Social networking channels, developer discussion forums, community platforms, and content aggregators.",
        "compliance_frameworks": ["GDPR", "CCPA", "Digital Services Act (EU DSA)", "COPPA"],
        "security_priorities": ["Account Takeover Protection", "Content Moderation APIs & Anti-Abuse", "Graph API / Access Token Security", "CORS & CSRF Hardening"],
        "threat_vectors": ["Mass Scrapes of User Profiles", "Automated Spambots & Astroturfing", "Session Hijacking / Token Thefts", "Cross-Site Scripting (XSS)"],
        "domain_patterns": [
            r"reddit", r"twitter", r"x\.com", r"linkedin", r"instagram", r"facebook",
            r"pinterest", r"discord", r"tiktok", r"quora", r"stackoverflow", r"medium",
            r"tumblr", r"threads\.net", r"snapchat", r"mastodon", r"bluesky", r"discourse"
        ],
        "title_keywords": [
            "social network", "community forum", "discussion board", "join the community",
            "connect with friends", "ask questions", "developer community", "share posts",
            "online community", "public feed"
        ],
        "body_keywords": [
            "sign up to join", "user profile", "followers", "following", "upvote",
            "downvote", "comments section", "leave a reply", "share post", "trending topics",
            "community guidelines", "direct message", "feed", "hashtags", "ask a question"
        ]
    },
    "Travel & Hospitality": {
        "icon": "✈️",
        "industry": "Travel, Tourism & Hospitality",
        "description": "Airlines, hotel booking engines, travel aggregators, vacation rental services, and tourism portals.",
        "compliance_frameworks": ["PCI-DSS", "GDPR (Traveler PII)", "IATA Cybersecurity Standards"],
        "security_priorities": ["Booking API Rate Limiting", "Cardholder Data Isolation", "Account Protection for Loyalty Points", "Anti-Scraping for Fare Data"],
        "threat_vectors": ["Frequent Flyer & Loyalty Account Draining", "Seat / Fare Scraping Bots", "Phishing with Fake Booking Confirmations", "Magecart on Booking Checkouts"],
        "domain_patterns": [
            r"expedia", r"booking\.com", r"airbnb", r"tripadvisor", r"agoda",
            r"makemytrip", r"kayak", r"trivago", r"hotels\.com", r"delta\.com",
            r"emirates", r"indigo", r"airindia", r"united\.com", r"aa\.com",
            r"marriott", r"hilton", r"hyatt", r"hostelworld", r"skyscanner", r"yatra"
        ],
        "title_keywords": [
            "hotel booking", "cheap flights", "vacation rentals", "travel guide",
            "airline tickets", "resorts", "holidays & tours", "book a stay",
            "flight status", "travel agency", "destinations"
        ],
        "body_keywords": [
            "check-in", "check-out", "hotel booking", "flight ticket", "departure",
            "arrival", "round trip", "one way", "passenger details", "room tariff",
            "guest rating", "vacation package", "car rental", "tourist visa",
            "luggage allowance", "boarding pass", "airport transfer", "amenities"
        ]
    },
    "Entertainment & Streaming": {
        "icon": "🎬",
        "industry": "Media, Streaming & Entertainment",
        "description": "Video streaming platforms, music services, digital entertainment portals, anime, and podcasts.",
        "compliance_frameworks": ["DMCA / DRM Standards", "GDPR", "COPPA", "PCI-DSS for Subscriptions"],
        "security_priorities": ["Digital Rights Management (DRM) Integrity", "Credential Stuffing & Subscription Sharing Prevention", "Content Delivery CDN Security"],
        "threat_vectors": ["Premium Account Takeover & Resale", "Content Piracy & Stream Ripping", "DDoS on High-Profile Release Premieres"],
        "domain_patterns": [
            r"netflix", r"spotify", r"hulu", r"disneyplus", r"youtube", r"twitch",
            r"crunchyroll", r"primevideo", r"hotstar", r"soundcloud", r"pandora",
            r"hbomax", r"paramountplus", r"appletv", r"vimeo", r"dailymotion", r"audible"
        ],
        "title_keywords": [
            "watch movies", "stream tv shows", "stream music", "watch anime",
            "live streaming", "original series", "listen to podcasts", "entertainment platform",
            "watch online", "binge watch", "on-demand video"
        ],
        "body_keywords": [
            "watch now", "stream now", "start your free trial", "episodes",
            "season", "trailers", "soundtrack", "subtitles", "play track",
            "playlist", "cast and crew", "genres", "offline download",
            "video quality", "ultra hd 4k", "now playing", "audiobook"
        ]
    },
    "Gaming & Esports": {
        "icon": "🎮",
        "industry": "Gaming & Esports",
        "description": "Video game publishers, digital game distribution storefronts, esports tournaments, and gaming communities.",
        "compliance_frameworks": ["COPPA", "GDPR", "PCI-DSS (In-Game Microtransactions)"],
        "security_priorities": ["Anti-Cheat & Binary Integrity", "DDoS Protection for Multiplayer Game Servers", "In-Game Currency & Inventory Fraud Prevention"],
        "threat_vectors": ["Game Server DDoS Attacks", "Account Hijacking for Rare Skins/In-Game Goods", "Game Cracks, Keygens & Supply Chain Malware"],
        "domain_patterns": [
            r"steam", r"steampowered", r"epicgames", r"roblox", r"riotgames",
            r"blizzard", r"ea\.com", r"ubisoft", r"playstation", r"xbox",
            r"nintendo", r"ign\.com", r"gamespot", r"pcgamer", r"gog\.com",
            r"unity\.com", r"unrealengine", r"battlenet"
        ],
        "title_keywords": [
            "pc games", "video games", "multiplayer gaming", "esports tournament",
            "game store", "game downloads", "gaming news", "game console",
            "buy games", "play online games"
        ],
        "body_keywords": [
            "gameplay", "multiplayer", "single player", "game download",
            "system requirements", "dlc", "in-game purchase", "patch notes",
            "esports tournament", "leaderboard", "achievements", "graphics card",
            "fps", "beta test", "game mods", "early access"
        ]
    },
    "Non-Profit & NGO": {
        "icon": "🤝",
        "industry": "Non-Profit & Philanthropy",
        "description": "Charitable trusts, humanitarian non-profits, international aid NGOs, and philanthropic foundations.",
        "compliance_frameworks": ["PCI-DSS (Donations)", "GDPR (Donor Privacy)", "Charity Regulatory Reporting Standards"],
        "security_priorities": ["Donation Form / Payment Skimming Protection", "Donor Privacy Safeguarding", "Anti-Defacement Defenses"],
        "threat_vectors": ["Donation Page Fraud & Credit Card Testing", "Donor Information Dumps", "Impersonation Phishing Campaigns"],
        "domain_patterns": [
            r"redcross", r"unicef", r"amnesty", r"greenpeace", r"worldwildlife",
            r"oxfam", r"wikimedia", r"wikipedia", r"cry\.org", r"rotary",
            r"charitywater", r"giveindia", r"salvationarmy", r"doctorswithoutborders"
        ],
        "title_keywords": [
            "non-profit", "charity", "donate now", "humanitarian aid", "foundation",
            "volunteer", "philanthropy", "ngo", "support our mission", "community relief"
        ],
        "body_keywords": [
            "make a donation", "tax deductible", "donate online", "our mission",
            "volunteer with us", "annual impact", "charity work", "humanitarian crisis",
            "relief fund", "community outreach", "support families", "donate monthly",
            "transparency report", "non-governmental organization"
        ]
    }
}

# Metadata fallback for "Other" / Generic Websites
DEFAULT_CATEGORY_META = {
    "icon": "🌐",
    "industry": "General Web & Services",
    "description": "General website, personal portfolio, or business landing page.",
    "compliance_frameworks": ["GDPR", "Standard Web Security Standards"],
    "security_priorities": ["Baseline TLS Hardening", "Standard HTTP Security Headers", "CMS & Dependency Updates"],
    "threat_vectors": ["General Phishing & Social Engineering", "Brute-force Login Attempts", "Known CVE Exploitation"]
}


def detect_category_details(
    url: str,
    page_title: str = "",
    meta_description: str = "",
    page_text: str = ""
) -> Dict[str, Any]:
    """
    Performs comprehensive multi-signal category detection and returns rich classification metadata.
    
    Returns a dictionary containing:
      - category: Primary detected category name (e.g. 'News & Media')
      - confidence: High / Medium / Low / None
      - confidence_score: Calculated score for best category
      - icon: Category emoji symbol
      - industry: Broader sector name
      - description: Category overview
      - compliance_frameworks: Relevant regulatory standards (HIPAA, PCI-DSS, etc.)
      - security_priorities: Critical security controls for this domain type
      - threat_vectors: Typical attack surfaces
      - matched_signals: Breakdown of matched TLD, domain, title, and body signals
      - all_scores: Raw scores for all categories evaluated
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
    matched_signals_by_cat = {}

    for cat, cfg in CATEGORY_CONFIG.items():
        score = 0
        signals = {
            "tld_matched": False,
            "domain_patterns_matched": [],
            "title_keywords_matched": [],
            "body_keywords_matched": []
        }

        # 1. TLD score (weight = 6 points)
        for tld in DOMAIN_TLD_RULES.get(cat, []):
            if domain.endswith(tld) or f"{tld}." in domain:
                score += 6
                signals["tld_matched"] = True
                break

        # 2. Domain pattern match (weight = 5 points)
        for pattern in cfg.get("domain_patterns", []):
            if re.search(pattern, domain_name) or re.search(pattern, domain):
                score += 5
                signals["domain_patterns_matched"].append(pattern)
                break

        # 3. Title & Meta keywords (weight = 3-4 points each)
        for t_kw in cfg.get("title_keywords", []):
            if " " in t_kw:
                if t_kw in header_content:
                    score += 4
                    signals["title_keywords_matched"].append(t_kw)
            else:
                if re.search(rf"\b{re.escape(t_kw)}\b", header_content):
                    score += 3
                    signals["title_keywords_matched"].append(t_kw)

        # 4. Body text keywords (capped per keyword to avoid keyword stuffing)
        for b_kw in cfg.get("body_keywords", []):
            if " " in b_kw:
                count = body_clean.count(b_kw)
                if count > 0:
                    pts = min(count * 2, 6)
                    score += pts
                    signals["body_keywords_matched"].append(f"{b_kw} (x{count})")
            else:
                matches = len(re.findall(rf"\b{re.escape(b_kw)}\b", body_clean))
                if matches > 0:
                    pts = min(matches, 3)
                    score += pts
                    signals["body_keywords_matched"].append(f"{b_kw} (x{matches})")

        if score > 0:
            scores[cat] = score
            matched_signals_by_cat[cat] = signals

    # Threshold evaluation
    MIN_THRESHOLD = 3
    valid_scores = {k: v for k, v in scores.items() if v >= MIN_THRESHOLD}

    if not valid_scores:
        return {
            "category": "Other",
            "confidence": "Low",
            "confidence_score": 0,
            "icon": DEFAULT_CATEGORY_META["icon"],
            "industry": DEFAULT_CATEGORY_META["industry"],
            "description": DEFAULT_CATEGORY_META["description"],
            "compliance_frameworks": DEFAULT_CATEGORY_META["compliance_frameworks"],
            "security_priorities": DEFAULT_CATEGORY_META["security_priorities"],
            "threat_vectors": DEFAULT_CATEGORY_META["threat_vectors"],
            "matched_signals": {},
            "all_scores": scores
        }

    # Best matched category
    best_cat = max(valid_scores, key=valid_scores.get)
    best_score = valid_scores[best_cat]
    best_meta = CATEGORY_CONFIG.get(best_cat, DEFAULT_CATEGORY_META)

    # Confidence rating
    if best_score >= 10:
        confidence = "High"
    elif best_score >= 6:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "category": best_cat,
        "confidence": confidence,
        "confidence_score": best_score,
        "icon": best_meta.get("icon", "🌐"),
        "industry": best_meta.get("industry", "General Web"),
        "description": best_meta.get("description", ""),
        "compliance_frameworks": best_meta.get("compliance_frameworks", []),
        "security_priorities": best_meta.get("security_priorities", []),
        "threat_vectors": best_meta.get("threat_vectors", []),
        "matched_signals": matched_signals_by_cat.get(best_cat, {}),
        "all_scores": scores
    }


def detect_category(
    url: str,
    page_title: str = "",
    meta_description: str = "",
    page_text: str = ""
) -> str:
    """
    Standard function returning the primary category string.
    Ensures seamless backward compatibility with existing scanner pipelines.
    """
    details = detect_category_details(url, page_title, meta_description, page_text)
    return details["category"]


def get_category_metadata(category: str) -> Dict[str, Any]:
    """
    Retrieves full metadata dictionary for a given category name.
    """
    if category in CATEGORY_CONFIG:
        meta = CATEGORY_CONFIG[category].copy()
        meta["category"] = category
        return meta
    return {
        "category": "Other",
        **DEFAULT_CATEGORY_META
    }


def get_all_categories() -> List[Dict[str, Any]]:
    """
    Returns a list of all supported categories with their metadata and icons.
    """
    categories_list = []
    for cat, cfg in CATEGORY_CONFIG.items():
        categories_list.append({
            "category": cat,
            "icon": cfg.get("icon", "🌐"),
            "industry": cfg.get("industry", ""),
            "description": cfg.get("description", ""),
            "compliance_frameworks": cfg.get("compliance_frameworks", []),
            "security_priorities": cfg.get("security_priorities", [])
        })
    categories_list.append({
        "category": "Other",
        **DEFAULT_CATEGORY_META
    })
    return categories_list
