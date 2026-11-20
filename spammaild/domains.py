"""Alan adı yardımcıları. Kamu son ek listesi pakette gelen kopyadan okunur; ağ kullanılmaz."""

from __future__ import annotations

import ipaddress
from functools import lru_cache

import tldextract

# suffix_list_urls=() ağdan indirmeyi kapatır; pakete gömülü PSL kopyası kullanılır.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


@lru_cache(maxsize=4096)
def registered_domain(host: str) -> str:
    """eTLD+1 değerini döner (ör. `paypal.com.evil.io` → `evil.io`). IP ya da boş adda boş dize."""
    host = host.strip().strip(".").lower()
    if not host or is_ip_literal(host):
        return ""
    result = _EXTRACT(host)
    if result.top_domain_under_public_suffix:
        return result.top_domain_under_public_suffix
    # Son ek listesinde olmayan ad (ör. ayrılmış `.example`, `.test`): son iki etiket.
    return ".".join(host.split(".")[-2:]) if "." in host else ""


def same_organization(host_a: str, host_b: str) -> bool:
    """İki adres aynı kayıtlı alan adına mı ait? Alt dize değil, eşitlik karşılaştırması."""
    domain_a, domain_b = registered_domain(host_a), registered_domain(host_b)
    return bool(domain_a) and domain_a == domain_b
