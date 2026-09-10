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
    "Non-Profit & NGO": [".ngo", ".foundation", ".charity", ".gives", ".relief"]
}

# Category Configuration with Domain Patterns, Header Keywords, Content Keywords, and Sector Metadata
CATEGORY_CONFIG = {
    "Technology & SaaS": {
        "icon": "💻",
        "industry": "Technology, Cloud & SaaS",
        "description": "Software products, cloud infrastructure providers, developer tooling platforms, AI applications, tech giants, and APIs.",
        "compliance_frameworks": ["SOC 2 Type II", "ISO 27001", "ISO 27017 / 27018", "FedRAMP", "GDPR", "CCPA"],
        "security_priorities": ["API Gateway & Token Auth Hardening", "Strict Content-Security-Policy", "Zero-Trust Architecture", "CORS Policy Restriction & CSRF Defense"],
        "threat_vectors": ["API Key Leaks & Unauthorized Scraping", "Supply Chain / Dependency Compromise", "Server-Side Request Forgery (SSRF)", "Session Hijacking / OAuth Abuse"],
        "domain_patterns": [
            r"microsoft", r"apple", r"google", r"alphabet", r"meta", r"openai", r"anthropic",
            r"deepmind", r"huggingface", r"github", r"gitlab", r"bitbucket", r"atlassian",
            r"jira", r"confluence", r"trello", r"slack", r"notion", r"vercel", r"netlify",
            r"render", r"railway", r"supabase", r"firebase", r"aws", r"azure", r"cloudflare",
            r"fastly", r"akamai", r"salesforce", r"docker", r"kubernetes", r"hashicorp",
            r"datadog", r"sentry", r"newrelic", r"dynatrace", r"splunk", r"grafana",
            r"mongodb", r"redis", r"elastic", r"digitalocean", r"linode", r"vultr", r"hetzner",
            r"heroku", r"postman", r"insomnia", r"swagger", r"figma", r"canva", r"miro",
            r"linear", r"asana", r"monday", r"clickup", r"snowflake", r"databricks",
            r"twilio", r"sendgrid", r"segment", r"hubspot", r"zendesk", r"freshworks",
            r"zoom", r"ibm", r"oracle", r"sap", r"cisco", r"intel", r"nvidia", r"amd",
            r"qualcomm", r"broadcom", r"arm", r"hp\.com", r"dell", r"lenovo", r"asus",
            r"adobe", r"autodesk", r"jetbrains", r"mozilla", r"apache", r"linux",
            r"ubuntu", r"debian", r"redhat", r"canonical", r"stackoverflow", r"w3schools",
            r"snyk", r"sonarqube", r"hackerone", r"bugcrowd", r"auth0", r"okta", r"dropbox", r"box\.com"
        ],
        "title_keywords": [
            "software", "saas platform", "cloud platform", "developer tools", "api documentation",
            "open source", "devops", "sdk", "workflow automation", "enterprise software",
            "artificial intelligence", "machine learning", "cybersecurity platform", "data analytics",
            "computers, apps", "cloud computing", "technology solutions", "generative ai"
        ],
        "body_keywords": [
            "api documentation", "developer docs", "cloud infrastructure",
            "continuous integration", "open source", "rest api", "graphql", "webhooks",
            "sign up free", "start free trial", "enterprise software",
            "system uptime", "command line", "deployment", "github repository", "cloud computing"
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
            r"walmart", r"target", r"aliexpress", r"alibaba", r"temu", r"myntra", r"meesho",
            r"ajio", r"nykaa", r"shopify", r"bigcommerce", r"woocommerce", r"magento",
            r"bestbuy", r"costco", r"homedepot", r"lowes", r"ikea", r"wayfair", r"asos",
            r"zalando", r"shein", r"zara", r"hm\.com", r"rakuten", r"mercadolibre",
            r"jd\.com", r"newegg", r"chewy", r"nike", r"adidas", r"puma", r"uniqlo", r"sephora"
        ],
        "title_keywords": [
            "online shopping", "shop online", "store", "buy online", "ecommerce",
            "shopping cart", "marketplace", "online store", "free shipping",
            "deals & discounts", "retail store"
        ],
        "body_keywords": [
            "add to cart", "shopping cart", "proceed to checkout", "buy now", "order now",
            "free shipping", "product catalog", "customer reviews", "return policy",
            "cash on delivery", "add to wishlist", "discount code", "track order",
            "in stock", "out of stock", "secure checkout"
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
            r"bank", r"chase", r"bankofamerica", r"wellsfargo", r"citi", r"citigroup",
            r"goldmansachs", r"morganstanley", r"jpmorgan", r"barclays", r"hsbc", r"santander",
            r"bnp", r"ubs", r"hdfc", r"icici", r"sbi\.co", r"statebankofindia", r"axisbank",
            r"kotak", r"capitalone", r"americanexpress", r"mastercard", r"visa", r"revolut",
            r"monzo", r"wise\.com", r"stripe", r"paypal", r"razorpay", r"paytm", r"phonepe",
            r"zerodha", r"groww", r"upstox", r"robinhood", r"coinbase", r"binance", r"kraken",
            r"fidelity", r"vanguard", r"schwab", r"blackrock", r"fintech"
        ],
        "title_keywords": [
            "banking", "online banking", "personal banking", "credit card", "debit card",
            "savings account", "current account", "fixed deposit", "wealth management",
            "investments", "stock trading", "payment gateway", "fintech", "mutual funds",
            "net banking", "mobile banking"
        ],
        "body_keywords": [
            "online banking", "net banking", "savings account", "checking account",
            "credit score", "interest rate", "fixed deposit", "mutual funds",
            "home loan", "personal loan", "money transfer", "swift code",
            "ifsc code", "routing number", "cardholder", "atm locator",
            "demat account", "kyc verification", "financial advisor"
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
            r"hospital", r"clinic", r"healthcare", r"apollohospitals", r"fortishealthcare",
            r"mayoclinic", r"clevelandclinic", r"hopkinsmedicine", r"mountsinai", r"webmd",
            r"practo", r"1mg", r"tata1mg", r"pharma", r"aiims", r"maxhealthcare",
            r"manipalhospitals", r"medanta", r"narayanahealth", r"healthline",
            r"pharmasy", r"netmeds", r"medplus", r"diagnostic", r"pathology",
            r"telehealth", r"telemedicine", r"kaiserpermanente", r"cvshealth",
            r"walgreens", r"pfizer", r"moderna", r"novartis", r"roche"
        ],
        "title_keywords": [
            "hospital", "medical center", "patient care", "health system", "specialty clinic",
            "medical college hospital", "multi-specialty hospital", "medical sciences",
            "telehealth", "find a doctor", "clinical care", "patient portal"
        ],
        "body_keywords": [
            "medical care", "patient care", "inpatient", "outpatient",
            "cardiology", "oncology", "pediatrics", "neurology", "intensive care unit",
            "diagnostic tests", "mri scan", "ct scan", "medical history",
            "clinical treatment", "emergency department", "healthcare services"
        ]
    },
    "Education": {
        "icon": "🎓",
        "industry": "Education & EdTech",
        "description": "Academic institutions, universities, schools, learning portals, and online course providers.",
        "compliance_frameworks": ["FERPA", "COPPA", "GDPR-K", "ISO 27001"],
        "security_priorities": ["Student PII Protection", "LMS Authentication Hardening", "Anti-Phishing", "DDoS Mitigation during Exam/Admission Periods"],
        "threat_vectors": ["Credential Stuffing on Student Portals", "Ransomware on Academic Networks", "Data Leaks of Research Data"],
        "domain_patterns": [
            r"univ", r"college", r"academy", r"campus", r"sppu", r"unipune",
            r"iit\.", r"iitb", r"iitd", r"iitm", r"iitk", r"nit\.", r"mit\.edu",
            r"stanford", r"harvard", r"oxford", r"cambridge", r"berkeley", r"yale",
            r"princeton", r"columbia\.edu", r"cornell", r"caltech", r"coursera",
            r"udemy", r"edx\.org", r"udacity", r"khanacademy", r"blackboard",
            r"moodle", r"duolingo", r"quizlet", r"chegg", r"byjus", r"unacademy",
            r"leetcode", r"codecademy", r"pluralsight", r"skillshare", r"edutech"
        ],
        "title_keywords": [
            "university", "academic portal", "institute of technology",
            "student admissions", "academics & courses", "syllabus & curriculum",
            "learning management system", "online degrees", "academic calendar", "higher education"
        ],
        "body_keywords": [
            "academic curriculum", "student admissions", "undergraduate program",
            "postgraduate degree", "tuition fees", "academic calendar",
            "course catalog", "doctoral program", "student enrollment",
            "academic faculty", "scholarships & financial aid", "accredited degree"
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
            r"usa\.gov", r"whitehouse\.gov", r"irs\.gov", r"state\.gov", r"sec\.gov",
            r"fda\.gov", r"fbi\.gov", r"nasa\.gov", r"gov\.uk", r"nhs\.uk", r"canada\.ca"
        ],
        "title_keywords": [
            "ministry of", "department of", "official government portal",
            "citizen services", "national portal", "government of india",
            "federal government", "public administration", "official government website"
        ],
        "body_keywords": [
            "ministry of", "department of", "government of", "citizen services",
            "official portal", "public services", "national portal", "e-governance",
            "gazette", "statutory body", "municipal corporation", "public grievances",
            "aadhaar card", "passport services", "income tax filing"
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
            r"nytimes", r"washingtonpost", r"wsj", r"bloomberg", r"reuters", r"apnews",
            r"bbc", r"cnn", r"foxnews", r"nbcnews", r"abcnews", r"theguardian", r"telegraph",
            r"independent\.co", r"dailymail", r"aljazeera", r"hindustantimes", r"thehindu",
            r"indianexpress", r"timesofindia", r"indiatoday", r"ndtv", r"news18", r"firstpost",
            r"forbes", r"fortune", r"time\.com", r"theatlantic", r"economist", r"usatoday",
            r"latimes", r"politico", r"huffpost", r"buzzfeed", r"vox\.com"
        ],
        "title_keywords": [
            "breaking news", "latest news", "world news", "daily news", "journalism",
            "headlines", "press release", "live news updates", "investigative reports"
        ],
        "body_keywords": [
            "breaking news", "read full story", "latest news updates", "journalist",
            "reporter", "editorial team", "world news", "live coverage",
            "published on", "investigative report", "front page news"
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
            r"zillow", r"realtor", r"redfin", r"trulia", r"compass\.com", r"magicbricks",
            r"99acres", r"housing\.com", r"nobroker", r"commonfloor", r"squareyards",
            r"proptiger", r"rightmove", r"zoopla", r"century21", r"apartments\.com"
        ],
        "title_keywords": [
            "real estate", "homes for sale", "realtor", "flats for sale",
            "properties for rent", "commercial spaces", "luxury villas", "new residential projects"
        ],
        "body_keywords": [
            "property for sale", "properties for rent", "apartments for rent",
            "houses for sale", "buy flat", "villa for sale", "sq ft",
            "square feet", "residential property", "commercial property",
            "property listings", "floor plan", "rera registered"
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
            r"mckinsey", r"bcg\.com", r"bostonconsulting", r"bain", r"deloitte", r"kpmg",
            r"pwc", r"ey\.com", r"accenture", r"capgemini", r"cognizant", r"tcs\.com",
            r"infosys", r"wipro", r"hcltech", r"techmahindra", r"gartner", r"boozallen"
        ],
        "title_keywords": [
            "management consulting", "enterprise solutions", "global consulting",
            "corporate advisory", "b2b professional services", "strategic advisory"
        ],
        "body_keywords": [
            "management consulting", "enterprise solutions", "corporate governance",
            "digital transformation consulting", "investor relations", "annual report",
            "shareholder value", "sustainability report"
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
            r"facebook", r"instagram", r"threads\.net", r"whatsapp", r"twitter",
            r"x\.com", r"linkedin", r"reddit", r"pinterest", r"tiktok",
            r"snapchat", r"discord", r"telegram", r"signal\.org", r"quora",
            r"tumblr", r"bluesky", r"mastodon", r"discourse"
        ],
        "title_keywords": [
            "social network", "community forum", "discussion board", "join the community",
            "connect with friends", "share posts", "online community"
        ],
        "body_keywords": [
            "sign up to join", "user profile", "followers", "upvote", "downvote",
            "comments section", "leave a reply", "share post", "trending topics",
            "community guidelines", "direct message"
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
            r"booking\.com", r"airbnb", r"expedia", r"tripadvisor", r"agoda",
            r"makemytrip", r"kayak", r"trivago", r"hotels\.com", r"skyscanner",
            r"yatra", r"cleartrip", r"marriott", r"hilton", r"hyatt", r"emirates",
            r"qatarairways", r"delta\.com", r"united\.com", r"aa\.com", r"airindia",
            r"indigo\.in", r"uber\.com", r"lyft\.com"
        ],
        "title_keywords": [
            "hotel booking", "cheap flights", "vacation rentals", "travel guide",
            "airline tickets", "resorts & hotels", "holidays & tours", "book a stay"
        ],
        "body_keywords": [
            "hotel booking", "flight ticket", "departure date", "round trip",
            "passenger details", "vacation package", "car rental", "tourist visa",
            "boarding pass", "airport transfer"
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
            r"netflix", r"spotify", r"hulu", r"disneyplus", r"disney\.com", r"youtube",
            r"twitch", r"crunchyroll", r"primevideo", r"hotstar", r"soundcloud",
            r"pandora", r"hbomax", r"paramountplus", r"appletv", r"vimeo", r"dailymotion",
            r"audible", r"imdb"
        ],
        "title_keywords": [
            "watch movies", "stream tv shows", "stream music", "watch anime",
            "live streaming", "original series", "listen to podcasts", "entertainment platform"
        ],
        "body_keywords": [
            "watch now", "stream now", "episodes", "trailers",
            "soundtrack", "play track", "playlist", "cast and crew", "ultra hd 4k"
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
            r"steampowered", r"steamcommunity", r"epicgames", r"roblox", r"riotgames",
            r"blizzard", r"battlenet", r"ea\.com", r"ubisoft", r"playstation",
            r"xbox\.com", r"nintendo", r"ign\.com", r"gamespot", r"pcgamer",
            r"gog\.com", r"unity\.com", r"unrealengine"
        ],
        "title_keywords": [
            "pc games", "video games", "multiplayer gaming", "esports tournament",
            "game store", "game downloads", "gaming news", "game console", "play online games"
        ],
        "body_keywords": [
            "gameplay", "multiplayer game", "single player", "game download",
            "system requirements", "dlc", "in-game purchase", "patch notes",
            "esports tournament", "leaderboard", "beta test"
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
            r"wwf\.org", r"oxfam", r"wikimedia", r"wikipedia", r"rotary",
            r"charitywater", r"giveindia", r"salvationarmy", r"doctorswithoutborders"
        ],
        "title_keywords": [
            "non-profit organization", "charity foundation", "donate now",
            "humanitarian aid", "philanthropy", "support our mission", "community relief"
        ],
        "body_keywords": [
            "make a donation", "tax deductible", "donate online", "our mission",
            "volunteer with us", "annual impact", "charity work", "humanitarian crisis",
            "relief fund", "support families", "donate monthly"
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


def _matches_domain_pattern(pattern: str, domain: str) -> bool:
    """
    Checks if a pattern matches a domain or any of its subdomains cleanly.
    """
    # Exact regex search if pattern contains special regex syntax
    if "\\" in pattern or "^" in pattern or "$" in pattern:
        return bool(re.search(pattern, domain))
    
    # Clean token search on domain labels (e.g. 'apple' matches 'apple.com', 'www.apple.com', 'store.apple.co.uk')
    domain_labels = domain.split(".")
    if pattern in domain_labels:
        return True
    
    # Or matches as bounded regex
    return bool(re.search(rf"(?:^|\.){re.escape(pattern)}(?:\.|$)", domain))


def detect_category_details(
    url: str,
    page_title: str = "",
    meta_description: str = "",
    page_text: str = ""
) -> Dict[str, Any]:
    """
    Performs comprehensive multi-signal category detection and returns rich classification metadata.
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

        # 1. Domain pattern match (Weight = 15 points -> High confidence)
        for pattern in cfg.get("domain_patterns", []):
            if _matches_domain_pattern(pattern, domain):
                score += 15
                signals["domain_patterns_matched"].append(pattern)
                break

        # 2. TLD score (Weight = 12 points -> High confidence)
        for tld in DOMAIN_TLD_RULES.get(cat, []):
            if domain.endswith(tld) or f"{tld}." in domain:
                score += 12
                signals["tld_matched"] = True
                break

        # 3. Title & Meta keywords (Weight = 4-6 points each)
        for t_kw in cfg.get("title_keywords", []):
            if " " in t_kw:
                if t_kw in header_content:
                    score += 6
                    signals["title_keywords_matched"].append(t_kw)
            else:
                if re.search(rf"\b{re.escape(t_kw)}\b", header_content):
                    score += 4
                    signals["title_keywords_matched"].append(t_kw)

        # 4. Body text keywords (Capped at 6 max points total per category to prevent keyword stuffing)
        body_points = 0
        for b_kw in cfg.get("body_keywords", []):
            if " " in b_kw:
                count = body_clean.count(b_kw)
                if count > 0:
                    pts = min(count * 2, 4)
                    body_points += pts
                    signals["body_keywords_matched"].append(f"{b_kw} (x{count})")
            else:
                matches = len(re.findall(rf"\b{re.escape(b_kw)}\b", body_clean))
                if matches > 0:
                    pts = min(matches, 2)
                    body_points += pts
                    signals["body_keywords_matched"].append(f"{b_kw} (x{matches})")
        
        # Add capped body points
        score += min(body_points, 6)

        if score > 0:
            scores[cat] = score
            matched_signals_by_cat[cat] = signals

    # Threshold evaluation:
    # If domain/TLD/title matched -> score is >= 4
    # If only body matched -> requires at least 5 points (multiple distinct strong body signals)
    valid_scores = {}
    for k, v in scores.items():
        sig = matched_signals_by_cat.get(k, {})
        has_domain_or_tld_or_title = (
            sig.get("tld_matched") or 
            len(sig.get("domain_patterns_matched", [])) > 0 or 
            len(sig.get("title_keywords_matched", [])) > 0
        )
        if has_domain_or_tld_or_title and v >= 4:
            valid_scores[k] = v
        elif not has_domain_or_tld_or_title and v >= 5:
            valid_scores[k] = v

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
    if best_score >= 12:
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
