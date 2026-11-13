"""Web search, page fetching and downloads with SSRF protection."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse

import httpx

from .config import settings

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 IntunePackager/1.0"
TIMEOUT = httpx.Timeout(30.0, connect=15.0)


class BlockedURL(Exception):
    pass


async def _check_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise BlockedURL("only http(s) URLs are allowed")
    if settings.allow_private_urls:
        return
    host = parsed.hostname
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BlockedURL(f"cannot resolve {host}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise BlockedURL(f"{host} resolves to a non-public address ({ip})")


async def _get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    """GET with manual redirect handling so every hop is SSRF-checked."""
    for _ in range(6):
        await _check_url(url)
        resp = await client.get(url, follow_redirects=False, **kwargs)
        if resp.is_redirect and "location" in resp.headers:
            url = urljoin(url, resp.headers["location"])
            continue
        return resp
    raise BlockedURL("too many redirects")


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT, "Accept-Language": "en,de;q=0.8"})


# ---------------------------------------------------------------- HTML -> text
class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head", "template"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "section", "article", "table", "dt", "dd"}

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._skip = 0
        self._href: str | None = None
        self._link_text: list[str] = []
        self.base = base_url

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        if tag in self.BLOCK:
            self.parts.append("\n")
        if tag == "a":
            href = dict(attrs).get("href")
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self._href = urljoin(self.base, href)
                self._link_text = []
        if tag == "code":
            self.parts.append("`")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        if tag == "code":
            self.parts.append("`")
        if tag == "a" and self._href:
            text = " ".join("".join(self._link_text).split())
            if text:
                self.links.append((text[:80], self._href))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._link_text.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        return re.sub(r"\n\s*\n+", "\n\n", raw).strip()


async def fetch_text(url: str, max_chars: int = 25_000, offset: int = 0) -> str:
    async with _client() as client:
        resp = await _get(client, url)
    ctype = resp.headers.get("content-type", "")
    if resp.status_code >= 400:
        return f"HTTP {resp.status_code} for {url}"
    if "html" in ctype or resp.text.lstrip().startswith("<"):
        parser = _TextExtractor(str(resp.url))
        parser.feed(resp.text)
        text = parser.text()
        links = "\n".join(f"- {t}: {h}" for t, h in parser.links[:80])
        text = text + ("\n\n[Links on page]\n" + links if links else "")
    elif "json" in ctype or "text" in ctype or "xml" in ctype:
        text = resp.text
    else:
        return f"[{url} is not a text page: content-type {ctype}, {len(resp.content)} bytes. Use download_file for binaries.]"
    chunk = text[offset: offset + max_chars]
    if len(text) > offset + max_chars:
        chunk += f"\n[... truncated, {len(text)} chars total; call again with offset={offset + max_chars}]"
    return f"URL: {resp.url}\n\n{chunk}"


# ------------------------------------------------------------------- search
async def web_search(query: str, max_results: int = 8) -> list[dict]:
    provider = settings.search_provider
    if provider == "auto":
        provider = (
            "tavily" if settings.tavily_api_key else
            "brave" if settings.brave_api_key else
            "searxng" if settings.searxng_url else
            "duckduckgo"
        )
    async with _client() as client:
        if provider == "tavily":
            resp = await client.post(
                "https://api.tavily.com/search",
                headers={"Authorization": f"Bearer {settings.tavily_api_key}"},
                json={"query": query, "max_results": max_results},
            )
            resp.raise_for_status()
            return [{"title": r.get("title"), "url": r.get("url"), "snippet": (r.get("content") or "")[:500]}
                    for r in resp.json().get("results", [])]
        if provider == "brave":
            resp = await client.get(
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": query, "count": max_results},
                headers={"X-Subscription-Token": settings.brave_api_key or "", "Accept": "application/json"},
            )
            resp.raise_for_status()
            return [{"title": r.get("title"), "url": r.get("url"), "snippet": re.sub("<[^>]+>", "", r.get("description", ""))}
                    for r in resp.json().get("web", {}).get("results", [])[:max_results]]
        if provider == "searxng":
            resp = await client.get(f"{settings.searxng_url.rstrip('/')}/search", params={"q": query, "format": "json"})
            resp.raise_for_status()
            return [{"title": r.get("title"), "url": r.get("url"), "snippet": r.get("content", "")[:500]}
                    for r in resp.json().get("results", [])[:max_results]]
        # DuckDuckGo HTML endpoint (no key; may be rate limited)
        resp = await client.post("https://html.duckduckgo.com/html/", data={"q": query})
        results = []
        for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>(.*?)(?=<a[^>]+class="result__a"|$)', resp.text, re.S):
            href, title, rest = m.groups()
            if "uddg=" in href:
                href = parse_qs(urlparse(unescape(href)).query).get("uddg", [href])[0]
            snippet = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', rest, re.S)
            results.append({
                "title": unescape(re.sub("<[^>]+>", "", title)).strip(),
                "url": unescape(href),
                "snippet": unescape(re.sub("<[^>]+>", "", snippet.group(1))).strip() if snippet else "",
            })
            if len(results) >= max_results:
                break
        if not results:
            raise RuntimeError("DuckDuckGo returned no results (possibly rate limited). Configure TAVILY_API_KEY, BRAVE_API_KEY or SEARXNG_URL.")
        return results


# ------------------------------------------------------------------ download
def _filename_from(resp: httpx.Response, url: str) -> str:
    cd = resp.headers.get("content-disposition", "")
    m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", cd)
    name = m.group(1) if m else Path(urlparse(str(resp.url)).path).name or Path(urlparse(url).path).name
    name = re.sub(r"[^\w.\- ()+]", "_", name).strip(" .") or "download.bin"
    return name[:150]


async def download(url: str, target_dir: Path, filename: str | None = None, max_mb: int | None = None) -> Path:
    max_bytes = (max_mb or settings.download_max_mb) * 1024 * 1024
    target_dir.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=20.0), headers={"User-Agent": USER_AGENT}) as client:
        for _ in range(6):
            await _check_url(url)
            async with client.stream("GET", url, follow_redirects=False) as resp:
                if resp.is_redirect and "location" in resp.headers:
                    url = urljoin(url, resp.headers["location"])
                    continue
                if resp.status_code >= 400:
                    raise RuntimeError(f"HTTP {resp.status_code} downloading {url}")
                length = int(resp.headers.get("content-length") or 0)
                if length > max_bytes:
                    raise RuntimeError(f"file is {length // 1024 // 1024} MB, limit is {max_bytes // 1024 // 1024} MB")
                name = filename or _filename_from(resp, url)
                target = target_dir / name
                size = 0
                with target.open("wb") as f:
                    async for chunk in resp.aiter_bytes(1024 * 1024):
                        size += len(chunk)
                        if size > max_bytes:
                            f.close()
                            target.unlink(missing_ok=True)
                            raise RuntimeError(f"download exceeds {max_bytes // 1024 // 1024} MB limit")
                        f.write(chunk)
                return target
    raise BlockedURL("too many redirects")


__all__ = ["web_search", "fetch_text", "download", "BlockedURL", "quote_plus"]
