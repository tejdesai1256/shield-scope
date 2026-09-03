import socket
import dns.resolver
from urllib.parse import urlparse


def scan_dns(url, pinned_ip=None):

    try:

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        hostname = urlparse(url).hostname
        if not hostname:
            return {"success": False, "error": "Invalid hostname"}

        result = {
            "success": True,
            "hostname": hostname
        }

        # IP Address
        if pinned_ip:
            result["ip_address"] = pinned_ip
        else:
            try:
                result["ip_address"] = socket.gethostbyname(hostname)
            except Exception:
                result["ip_address"] = "Not Found"

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.5
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

        # A Records
        try:
            answers = resolver.resolve(hostname, "A")
            result["A"] = [str(r) for r in answers]
        except Exception:
            result["A"] = [result["ip_address"]] if result.get("ip_address") and result["ip_address"] != "Not Found" else []

        # MX Records
        try:
            answers = resolver.resolve(hostname, "MX")
            result["MX"] = [str(r.exchange) for r in answers]
        except Exception:
            result["MX"] = []

        # NS Records
        try:
            answers = resolver.resolve(hostname, "NS")
            result["NS"] = [str(r.target) for r in answers]
        except Exception:
            result["NS"] = []

        # TXT Records
        try:
            answers = resolver.resolve(hostname, "TXT")
            result["TXT"] = [
                "".join(
                    txt.decode() if isinstance(txt, bytes) else txt
                    for txt in r.strings
                )
                for r in answers
            ]
        except Exception:
            result["TXT"] = []

        # SPF (from TXT records you already fetched)
        spf_record = next((t for t in result["TXT"] if t.lower().startswith("v=spf1")), None)
        result["spf_record"] = spf_record
        result["has_spf"] = spf_record is not None

        # DMARC (separate lookup)
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            dmarc_txt = "".join(
                r.strings[0].decode() if isinstance(r.strings[0], bytes) else r.strings[0]
                for r in dmarc_answers
            )
            result["dmarc_record"] = dmarc_txt
            result["has_dmarc"] = True
        except Exception:
            result["dmarc_record"] = None
            result["has_dmarc"] = False

        return result

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }