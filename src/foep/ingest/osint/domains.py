import logging
import socket
from typing import Generator

from foep.normalize.schema import Evidence, EntityType, ObservationType
from .virustotal import VirusTotalCollector
from .archiveorg import ArchiveOrgCollector
from .shodan import ShodanCollector
from .ipgeolocation import IPGeolocationCollector
from .whois_history import WHOISHistoryCollector

logger = logging.getLogger(__name__)

class DomainCollector:
    def __init__(self, config):
        self.config = config

    def check_domain(self, domain: str) -> Generator[Evidence, None, None]:
        # 1. DNS Resolution
        ip = None
        try:
            ip = socket.gethostbyname(domain)
            yield Evidence(
                evidence_id=f"dns::{domain}",
                entity_type=EntityType.DOMAIN,
                entity_value=domain,
                observation_type=ObservationType.OSINT_DNS,
                source="dns",
                metadata={"resolved_ip": ip},
                credibility_score=70,
                sha256_hash=None
            )
        except Exception as e:
            logger.warning(f"DNS resolution failed for {domain}: {e}")

        # 2. Enrich Domain
        virustotal_enabled = getattr(self.config.virustotal, 'enabled', False)
        if virustotal_enabled:
            vt_collector = VirusTotalCollector(self.config)
            yield from vt_collector.check_domain(domain)

        archiveorg_enabled = getattr(self.config.archiveorg, 'enabled', True)
        if archiveorg_enabled:
            archive_collector = ArchiveOrgCollector(self.config)
            yield from archive_collector.check_domain(domain)

        whois_enabled = getattr(self.config.whois_history, 'enabled', False)
        if whois_enabled:
            whois_collector = WHOISHistoryCollector(self.config)
            yield from whois_collector.check_domain(domain)

        # 3. Enrich IP (if resolved)
        if ip:
            shodan_enabled = getattr(self.config.shodan, 'enabled', False)
            if shodan_enabled:
                shodan_collector = ShodanCollector(self.config)
                yield from shodan_collector.check_ip(ip)
            
            geo_enabled = getattr(self.config.ipgeolocation, 'enabled', True)
            if geo_enabled:
                geo_collector = IPGeolocationCollector(self.config)
                yield from geo_collector.check_ip(ip)
