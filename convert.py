#!/usr/bin/env python3
import base64
import json
import os
import sys
import urllib.request
from urllib.parse import quote, urlencode

SOURCE_URL = os.environ.get("SOURCE_URL", "https://vpn.voidgram.xyz/burmalda")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "bur.txt")
NAME_PREFIX = os.environ.get("NAME_PREFIX", "proxy")
USER_AGENT = os.environ.get("USER_AGENT", "Mozilla/5.0")

BAD_ADDRESSES = {None, "", "127.0.0.1", "localhost", "0.0.0.0"}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace").strip()


def load_configs(raw):
    # на случай если источник отдаст base64
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)).decode())
    if isinstance(data, dict):
        data = [data]
    return data


def to_vless_parts(cfg):
    """Возвращает (ссылка_без_имени) или None."""
    for ob in cfg.get("outbounds", []):
        if ob.get("protocol") != "vless":
            continue
        try:
            vnext = ob["settings"]["vnext"][0]
            user = vnext["users"][0]
        except (KeyError, IndexError):
            continue

        address = vnext.get("address")
        port = vnext.get("port")
        uuid = user.get("id")
        if address in BAD_ADDRESSES or not uuid or not port:
            continue
        if uuid.startswith("00000000-0000"):
            continue

        ss = ob.get("streamSettings", {})
        network = ss.get("network", "tcp")
        security = ss.get("security", "none")

        params = {
            "encryption": user.get("encryption", "none"),
            "security": security,
            "type": network,
        }
        if user.get("flow"):
            params["flow"] = user["flow"]

        if security == "tls":
            tls = ss.get("tlsSettings", {})
            if tls.get("serverName"):
                params["sni"] = tls["serverName"]
            if tls.get("fingerprint"):
                params["fp"] = tls["fingerprint"]
            if tls.get("alpn"):
                params["alpn"] = ",".join(tls["alpn"])
            if tls.get("allowInsecure"):
                params["allowInsecure"] = "1"
        elif security == "reality":
            r = ss.get("realitySettings", {})
            if r.get("serverName"):
                params["sni"] = r["serverName"]
            if r.get("fingerprint"):
                params["fp"] = r["fingerprint"]
            if r.get("publicKey"):
                params["pbk"] = r["publicKey"]
            if r.get("shortId"):
                params["sid"] = r["shortId"]
            if r.get("spiderX"):
                params["spx"] = r["spiderX"]

        if network == "xhttp":
            x = ss.get("xhttpSettings", {})
            if x.get("host"):
                params["host"] = x["host"]
            if x.get("path"):
                params["path"] = x["path"]
            if x.get("mode"):
                params["mode"] = x["mode"]
        elif network == "ws":
            w = ss.get("wsSettings", {})
            if w.get("path"):
                params["path"] = w["path"]
            host = (w.get("headers") or {}).get("Host")
            if host:
                params["host"] = host
        elif network == "grpc":
            g = ss.get("grpcSettings", {})
            if g.get("serviceName"):
                params["serviceName"] = g["serviceName"]
        elif network == "tcp":
            tcp = ss.get("tcpSettings", {})
            if tcp.get("header", {}).get("type") == "http":
                params["headerType"] = "http"

        host_part = f"[{address}]" if ":" in address else address
        query = urlencode(params, quote_via=quote, safe="")
        return f"vless://{uuid}@{host_part}:{port}?{query}"

    return None


def main():
    try:
        configs = load_configs(fetch(SOURCE_URL))
    except Exception as e:
        print(f"Ошибка загрузки источника: {e}", file=sys.stderr)
        sys.exit(1)

    base_links, seen = [], set()
    for cfg in configs:
        link = to_vless_parts(cfg)
        if link and link not in seen:
            seen.add(link)
            base_links.append(link)

    if not base_links:
        print("Не удалось получить ни одной ссылки, bur.txt не трогаю", file=sys.stderr)
        sys.exit(1)

    links = [
        f"{link}#{quote(f'{NAME_PREFIX} {i}')}"
        for i, link in enumerate(base_links, start=1)
    ]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + "\n")

    print(f"Готово: {len(links)} конфигов -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
