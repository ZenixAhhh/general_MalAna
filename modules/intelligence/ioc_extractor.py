"""IOC (Indicators of Compromise) extraction utility."""

import re
import ipaddress


class IOCExtractor:
    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b')
    URL_REGEX = re.compile(r'https?://[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=%]+')
    SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
    MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')

    @classmethod
    def is_public_ip(cls, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
        except ValueError:
            return False

    @classmethod
    def extract_from_text(cls, text):
        iocs = {
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "sha256": set(),
            "md5": set()
        }

        # IPs
        for ip in cls.IP_REGEX.findall(text):
            if cls.is_public_ip(ip):
                iocs["ips"].add(ip)

        # URLs
        for url in cls.URL_REGEX.findall(text):
            iocs["urls"].add(url)

        # Domains
        for domain in cls.DOMAIN_REGEX.findall(text):
            if not any(domain in url for url in iocs["urls"]) and not cls.IP_REGEX.match(domain):
                if not domain.endswith((".exe", ".dll", ".sys", ".txt", ".csv", ".json", ".log", ".bat")):
                    iocs["domains"].add(domain)

        # Hashes
        for h in cls.SHA256_REGEX.findall(text):
            iocs["sha256"].add(h.lower())
        for h in cls.MD5_REGEX.findall(text):
            iocs["md5"].add(h.lower())

        return {k: sorted(list(v)) for k, v in iocs.items()}
