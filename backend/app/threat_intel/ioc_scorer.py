import math
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


class IoCConfidenceScorer:
    """Computes dynamic confidence scores and exponential time-decay for Threat IoCs."""

    SOURCE_WEIGHTS: Dict[str, float] = {
        "cisa": 1.0,
        "mandiant": 0.98,
        "crowdstrike": 0.98,
        "abusech": 0.92,
        "alienvault": 0.85,
        "taxii21": 0.88,
        "stix_feed": 0.85,
        "internal": 0.95,
        "custom_json": 0.75,
        "community": 0.70,
    }

    # Half life in days per IoC type before confidence decays by 50%
    HALF_LIFE_DAYS: Dict[str, float] = {
        "ip": 14.0,       # IPs rotate frequently
        "domain": 30.0,   # Domains are slightly more persistent
        "url": 21.0,      # Phishing URLs have short lifetimes
        "md5": 90.0,      # Hashes remain valid longer
        "sha256": 120.0,
        "email": 45.0,
    }

    @staticmethod
    def _normalize_utc(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def compute_composite_confidence(
        self,
        base_confidence: float,
        source: str,
        sightings_count: int = 0,
        feed_weight: Optional[float] = None,
    ) -> float:
        """Calculates normalized composite confidence (0.0 to 1.0) incorporating source reputation and sightings."""
        src_weight = feed_weight if feed_weight is not None else self.SOURCE_WEIGHTS.get(source.lower(), 0.80)
        
        # Sightings boost: up to +0.15 for verified multiple sightings
        sighting_boost = min(0.15, sightings_count * 0.03)
        
        raw_score = (base_confidence * src_weight) + sighting_boost
        return round(min(1.0, max(0.1, raw_score)), 3)

    def calculate_decayed_score(
        self,
        initial_score: float,
        ioc_type: str,
        last_seen: datetime,
        current_time: Optional[datetime] = None,
    ) -> float:
        """Calculates exponential time-decay score: S(t) = S_0 * 2^(-dt / half_life)."""
        now = self._normalize_utc(current_time) if current_time else datetime.now(timezone.utc)
        norm_last_seen = self._normalize_utc(last_seen)
        dt_days = max(0.0, (now - norm_last_seen).total_seconds() / 86400.0)
        half_life = self.HALF_LIFE_DAYS.get(ioc_type.lower(), 30.0)
        
        decay_factor = math.pow(2.0, -dt_days / half_life)
        decayed_score = initial_score * decay_factor
        return round(max(0.0, min(1.0, decayed_score)), 3)

    def is_ioc_expired(
        self,
        decayed_score: float,
        expires_at: Optional[datetime] = None,
        min_threshold: float = 0.20,
    ) -> bool:
        """Returns True if IoC has expired past explicit expiry date or decayed below minimum threshold."""
        if expires_at:
            norm_expires = self._normalize_utc(expires_at)
            if datetime.now(timezone.utc) > norm_expires:
                return True
        return decayed_score < min_threshold


ioc_scorer = IoCConfidenceScorer()
