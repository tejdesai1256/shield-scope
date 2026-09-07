import re
from urllib.parse import urlparse

# Category to keyword mapping
CATEGORY_KEYWORDS = {
    "Education": [
        "university", "college", "school", "campus", "admission",
        "syllabus", "faculty", "sppu", "edu"
    ],
    "Hospital": [
        "hospital", "clinic", "doctor", "patient", "appointment",
        "medical", "healthcare", "diagnosis", "treatment"
    ],
    "Real Estate": [
        "real estate", "property", "flat", "apartment", "villa",
        "rent", "builder", "sq ft", "realty"
    ],
    "E-commerce": [
        "cart", "checkout", "buy now", "add to cart", "shipping",
        "product", "price", "shop"
    ],
    "Corporate": [
        "about us", "our services", "clients", "careers",
        "solutions", "enterprise"
    ],
    "Government": [
        ".gov", "ministry", "government", "sarkar", "official portal",
        "citizen services"
    ],
    "Other": []
}


def detect_category(url: str, page_title: str = "", meta_description: str = "", page_text: str = "") -> str:
    """
    Detects website category based on domain name and page content (title, meta description, visible text).
    
    Weights:
      - Domain match: 2 points per hit
      - Page content / title / meta match: 1 point per occurrence
      
    Returns the category with the highest hit count, or 'Other' if no keywords match.
    """
    # Extract domain/hostname
    domain = ""
    try:
        if not url.startswith(("http://", "https://")):
            parsed = urlparse("https://" + url)
        else:
            parsed = urlparse(url)
        domain = (parsed.hostname or parsed.netloc or url).lower()
    except Exception:
        domain = (url or "").lower()

    # Combine content into lowercase text
    content_parts = [
        page_title or "",
        meta_description or "",
        page_text or ""
    ]
    combined_content = " ".join(content_parts).lower()

    scores = {}

    for category, keywords in CATEGORY_KEYWORDS.items():
        if category == "Other" or not keywords:
            continue

        score = 0
        for kw in keywords:
            kw_clean = kw.lower().strip()
            if not kw_clean:
                continue

            # Domain match check (weight = 2 points)
            if kw_clean.startswith("."):
                # e.g. .gov or .edu
                if domain.endswith(kw_clean) or f"{kw_clean}." in domain:
                    score += 2
            elif kw_clean in domain:
                score += 2

            # Content match check (weight = 1 point per occurrence)
            if kw_clean.startswith("."):
                occurrences = combined_content.count(kw_clean)
            elif " " in kw_clean:
                occurrences = combined_content.count(kw_clean)
            else:
                # Word boundary check for single words to avoid false positive partials
                occurrences = len(re.findall(rf"\b{re.escape(kw_clean)}\b", combined_content))

            if occurrences > 0:
                score += occurrences * 1

        if score > 0:
            scores[category] = score

    if not scores:
        return "Other"

    # Return category with highest score
    best_category = max(scores, key=scores.get)
    return best_category
