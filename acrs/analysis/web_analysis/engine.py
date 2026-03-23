from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from core.schemas import VulnerabilityFinding

SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS header",
    "content-security-policy": "Missing Content-Security-Policy header",
    "x-content-type-options": "Missing X-Content-Type-Options header",
    "x-frame-options": "Missing X-Frame-Options header",
    "referrer-policy": "Missing Referrer-Policy header",
}


class InputParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inputs = 0
        self.password_fields = 0
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.meta: dict[str, str] = {}
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()

        if t == "input":
            self.inputs += 1
            if attrs_map.get("type", "").lower() == "password":
                self.password_fields += 1

        if t == "a":
            href = attrs_map.get("href", "")
            if href:
                self.links.append(href)

        if t == "script":
            src = attrs_map.get("src", "")
            if src:
                self.scripts.append(src)

        if t == "meta":
            name = attrs_map.get("name", "") or attrs_map.get("property", "")
            content = attrs_map.get("content", "")
            if name and content:
                self.meta[name.lower()] = content

        if t == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


@dataclass(slots=True)
class WebAnalysisResult:
    summary: str
    data: dict
    findings: list[VulnerabilityFinding]


class WebSharpDetectionEngine:
    def analyze(self, website_url: str, max_pages: int = 20, max_depth: int = 1) -> WebAnalysisResult:
        findings: list[VulnerabilityFinding] = []
        parsed = urlparse(website_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("website_url must start with http:// or https://")

        queue: list[tuple[str, int]] = [(website_url, 0)]
        visited: set[str] = set()
        pages: list[dict] = []
        crawl_errors: list[str] = []
        total_inputs = 0
        total_password_fields = 0
        technologies: set[str] = set()

        while queue and len(pages) < max_pages:
            url, depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                status, headers, body = self._fetch(url)
            except Exception as exc:
                crawl_errors.append(f"{url}: {exc}")
                continue

            for header, message in SECURITY_HEADERS.items():
                if header not in headers:
                    findings.append(
                        VulnerabilityFinding(
                            title=message,
                            vulnerability_type="security-header",
                            severity="medium",
                            location=url,
                            evidence=f"Header `{header}` not present in response.",
                            confidence=0.86,
                        )
                    )

            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                if "secure" not in set_cookie.lower():
                    findings.append(
                        VulnerabilityFinding(
                            title="Cookie missing Secure flag",
                            vulnerability_type="cookie-security",
                            severity="medium",
                            location=url,
                            evidence="Set-Cookie header present without Secure flag.",
                            confidence=0.78,
                        )
                    )
                if "httponly" not in set_cookie.lower():
                    findings.append(
                        VulnerabilityFinding(
                            title="Cookie missing HttpOnly flag",
                            vulnerability_type="cookie-security",
                            severity="medium",
                            location=url,
                            evidence="Set-Cookie header present without HttpOnly flag.",
                            confidence=0.78,
                        )
                    )

            url_parsed = urlparse(url)
            if url_parsed.scheme != "https":
                findings.append(
                    VulnerabilityFinding(
                        title="Transport security is not HTTPS",
                        vulnerability_type="transport-security",
                        severity="high",
                        location=url,
                        evidence="Target uses HTTP; traffic may be intercepted.",
                        confidence=0.95,
                    )
                )

            parser = InputParser()
            parser.feed(body)

            total_inputs += parser.inputs
            total_password_fields += parser.password_fields

            if parser.password_fields > 0 and url_parsed.scheme != "https":
                findings.append(
                    VulnerabilityFinding(
                        title="Password input over insecure transport",
                        vulnerability_type="credential-exposure",
                        severity="high",
                        location=url,
                        evidence="Password fields detected while using non-HTTPS transport.",
                        confidence=0.9,
                    )
                )

            if "server" in headers:
                technologies.add(f"server:{headers['server']}")
            if "x-powered-by" in headers:
                technologies.add(f"powered-by:{headers['x-powered-by']}")
            for script in parser.scripts:
                low = script.lower()
                if "jquery" in low:
                    technologies.add("jquery")
                if "react" in low:
                    technologies.add("react")
                if "angular" in low:
                    technologies.add("angular")
                if "vue" in low:
                    technologies.add("vue")

            pages.append(
                {
                    "url": url,
                    "status": status,
                    "title": parser.title.strip()[:120],
                    "inputs": parser.inputs,
                    "password_fields": parser.password_fields,
                }
            )

            if depth < max_depth:
                for href in parser.links:
                    candidate = urljoin(url, href)
                    p = urlparse(candidate)
                    if p.netloc == parsed.netloc and p.scheme in {"http", "https"} and candidate not in visited:
                        queue.append((candidate, depth + 1))

        if not pages:
            raise RuntimeError(
                "Website analysis could not fetch any page from target. Confirm URL reachability and authorization."
            )

        special_files = self._probe_special_files(website_url)
        findings.extend(special_files["findings"])

        reflection_finding = self._check_reflection(website_url)
        if reflection_finding:
            findings.append(reflection_finding)

        summary = (
            f"Live web analysis completed: pages_scanned={len(pages)}, findings={len(findings)}, "
            f"inputs={total_inputs}, password_fields={total_password_fields}."
        )
        data = {
            "website_url": website_url,
            "pages_scanned": len(pages),
            "max_pages": max_pages,
            "max_depth": max_depth,
            "headers_checked": list(SECURITY_HEADERS.keys()),
            "form_inputs": total_inputs,
            "password_fields": total_password_fields,
            "pages": pages,
            "crawl_errors": crawl_errors,
            "detected_technologies": sorted(technologies),
            "special_files": special_files["artifacts"],
            "finding_count": len(findings),
        }
        return WebAnalysisResult(summary=summary, data=data, findings=findings)

    @staticmethod
    def _fetch(url: str) -> tuple[int, dict[str, str], str]:
        req = Request(url, headers={"User-Agent": "SNSX-CRS/1.0"})
        with urlopen(req, timeout=8) as resp:
            status = getattr(resp, "status", 200)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(300_000).decode("utf-8", errors="ignore")
        return status, headers, body

    def _probe_special_files(self, website_url: str) -> dict:
        base = urlparse(website_url)
        root = urlunparse((base.scheme, base.netloc, "", "", "", ""))
        probes = {
            "robots_txt": urljoin(root + "/", "robots.txt"),
            "security_txt": urljoin(root + "/", ".well-known/security.txt"),
            "sitemap_xml": urljoin(root + "/", "sitemap.xml"),
        }

        artifacts: dict[str, int | str] = {}
        findings: list[VulnerabilityFinding] = []
        for key, url in probes.items():
            try:
                status, _, _ = self._fetch(url)
                artifacts[key] = status
            except Exception:
                artifacts[key] = "unreachable"

        if artifacts.get("security_txt") != 200:
            findings.append(
                VulnerabilityFinding(
                    title="Missing security.txt disclosure file",
                    vulnerability_type="security-contact",
                    severity="low",
                    location=probes["security_txt"],
                    evidence=".well-known/security.txt not found or unreachable.",
                    confidence=0.84,
                )
            )

        return {"artifacts": artifacts, "findings": findings}

    def _check_reflection(self, website_url: str) -> VulnerabilityFinding | None:
        marker = "SNSX_REFLECT_7f12"
        parsed = urlparse(website_url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not query:
            query = {"q": ["test"]}
        key = next(iter(query.keys()))
        query[key] = [marker]
        updated_query = urlencode(query, doseq=True)
        probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, updated_query, parsed.fragment))

        try:
            _, _, body = self._fetch(probe_url)
        except Exception:
            return None

        if marker in body:
            return VulnerabilityFinding(
                title="Reflected untrusted input detected",
                vulnerability_type="reflected-input",
                severity="medium",
                location=probe_url,
                evidence="Injected marker appeared in response body without neutralization.",
                confidence=0.72,
            )
        return None
