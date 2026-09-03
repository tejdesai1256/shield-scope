import builtwith
from services.url_validator import safe_get
from bs4 import BeautifulSoup
import re

def scan_technology(url, pinned_ip=None):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        resp = safe_get(
            url,
            pinned_ip=pinned_ip,
            timeout=5,
            headers=headers
        )
        html_text = resp.text if (resp is not None and resp.text) else "<html></html>"
        headers_dict = dict(resp.headers) if (resp is not None and resp.headers) else {"content-type": "text/html"}

        technologies = {}
        try:
            # Pass explicit non-None headers and non-None html to prevent builtwith from falling back to urllib2
            technologies = builtwith.builtwith(url, headers=headers_dict, html=html_text)
        except Exception:
            technologies = {}

        if not isinstance(technologies, dict):
            technologies = {}

        # Enrich technologies with modern framework/CDN signatures
        server_hdr = headers_dict.get("Server") or headers_dict.get("server") or ""
        powered_by = headers_dict.get("X-Powered-By") or headers_dict.get("x-powered-by") or ""
        lower_html = html_text.lower()

        if "cloudflare" in server_hdr.lower() or "cf-ray" in headers_dict:
            technologies.setdefault("cdn", []).append("Cloudflare")
        if "github.com" in server_hdr.lower() or "github" in server_hdr.lower():
            technologies.setdefault("web-servers", []).append("GitHub.com")
        if "nginx" in server_hdr.lower():
            technologies.setdefault("web-servers", []).append("Nginx")
        if "apache" in server_hdr.lower():
            technologies.setdefault("web-servers", []).append("Apache")
        if "amazon" in server_hdr.lower() or "awselb" in lower_html or "cloudfront" in lower_html:
            technologies.setdefault("cdn", []).append("Amazon CloudFront / AWS")
        if "react" in lower_html or "_next" in lower_html:
            technologies.setdefault("javascript-frameworks", []).append("React")
        if "_next" in lower_html or "next.js" in lower_html:
            technologies.setdefault("web-frameworks", []).append("Next.js")
        if "vue" in lower_html:
            technologies.setdefault("javascript-frameworks", []).append("Vue.js")

        # Deduplicate lists
        for k in list(technologies.keys()):
            technologies[k] = list(dict.fromkeys(technologies[k]))

        additional_detection = {}
        try:
            soup = BeautifulSoup(html_text[:50000], "html.parser")
            generator_tag = soup.find("meta", attrs={"name": "generator"})
            additional_detection = {
                "server": server_hdr or None,
                "powered_by": powered_by or None,
                "generator": generator_tag.get("content") if generator_tag else None,
                "cookies_detected": list(resp.cookies.keys()) if (resp is not None and resp.cookies) else []
            }
        except Exception:
            pass

        return {
            "success": True,
            "technologies": technologies,
            "additional_detection": additional_detection
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

