import re
from url_analyzer.models import ParsedURL, Finding

def build_graph(parsed: ParsedURL, redirect_chain: list, findings: list[Finding]) -> dict:
    nodes_dict = {}
    edges = []
    
    def add_node(nid: str, ntype: str):
        if nid and nid not in nodes_dict:
            nodes_dict[nid] = {"id": nid, "type": ntype}

    add_node(parsed.raw, "url")
    
    actual_domain = ""
    if parsed.domain and parsed.suffix:
        actual_domain = f"{parsed.domain}.{parsed.suffix}"
    elif parsed.hostname:
        actual_domain = parsed.hostname

    if actual_domain:
        add_node(actual_domain, "actual_domain")
        
        if parsed.subdomain:
            full_subdomain = f"{parsed.subdomain}.{actual_domain}"
            add_node(full_subdomain, "subdomain")
            edges.append({"from": parsed.raw, "to": full_subdomain, "type": "hosted_on"})
            edges.append({"from": full_subdomain, "to": actual_domain, "type": "belongs_to"})
        else:
            edges.append({"from": parsed.raw, "to": actual_domain, "type": "hosted_on"})

    detected_brands = set()

    for f in findings:
        brand = None
        if f.check == "credentials_in_url":
            spoofed = f.evidence.split('@')[0]
            brand = spoofed.split('.')[0] if '.' in spoofed else spoofed
        elif f.check in ("brand_in_subdomain", "typosquat"):
            if "Brand:" in f.evidence:
                parts = f.evidence.split(',')
                for p in parts:
                    if "Brand:" in p:
                        brand = p.split(':')[1].strip()
            else:
                brand = f.evidence.strip()

        if brand:
            detected_brands.add(brand)

    for brand in detected_brands:
        add_node(brand, "brand")
        if actual_domain:
            edges.append({
                "from": brand,
                "to": actual_domain,
                "type": "trust_violation"
            })

    prev = parsed.raw
    for r in redirect_chain:
        url_str = r["url"] if isinstance(r, dict) and "url" in r else r
        if url_str != prev:
            add_node(url_str, "url")
            edges.append({
                "from": prev,
                "to": url_str,
                "type": "http_redirect"
            })
            prev = url_str

    unique_edges = []
    seen_edges = set()
    for e in edges:
        if not e.get("from") or not e.get("to") or e["from"] not in nodes_dict or e["to"] not in nodes_dict:
            continue
        key = (e["from"], e["to"], e["type"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    return {
        "nodes": list(nodes_dict.values()),
        "edges": unique_edges
    }
