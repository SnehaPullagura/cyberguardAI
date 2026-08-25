import pytest
from datetime import datetime, timedelta
from app.threat_intel.ioc_scorer import ioc_scorer


def test_ioc_confidence_composite_calculation():
    # Base confidence 0.8 from high-reputation source 'cisa' (weight 1.0)
    score_cisa = ioc_scorer.compute_composite_confidence(base_confidence=0.8, source="cisa", sightings_count=0)
    assert score_cisa >= 0.80

    # Sightings boost
    score_with_sightings = ioc_scorer.compute_composite_confidence(base_confidence=0.8, source="cisa", sightings_count=3)
    assert score_with_sightings > score_cisa

    # Community source with lower weight
    score_comm = ioc_scorer.compute_composite_confidence(base_confidence=0.8, source="community", sightings_count=0)
    assert score_comm < score_cisa


def test_ioc_feed_weight_override():
    # Feed weight explicit override
    score = ioc_scorer.compute_composite_confidence(base_confidence=0.9, source="custom", feed_weight=0.5)
    assert score <= 0.50


def test_ioc_all_types_half_life_decay():
    now = datetime.utcnow()
    initial = 1.0

    # Test IP (14d)
    decay_ip = ioc_scorer.calculate_decayed_score(initial, "ip", now - timedelta(days=14), now)
    assert 0.48 <= decay_ip <= 0.52

    # Test Domain (30d)
    decay_dom = ioc_scorer.calculate_decayed_score(initial, "domain", now - timedelta(days=30), now)
    assert 0.48 <= decay_dom <= 0.52

    # Test SHA256 (120d)
    decay_sha = ioc_scorer.calculate_decayed_score(initial, "sha256", now - timedelta(days=120), now)
    assert 0.48 <= decay_sha <= 0.52


def test_ioc_exponential_time_decay():
    initial = 1.0
    now = datetime.utcnow()

    # After 14 days, an IP IoC (half-life 14 days) should decay to ~0.50
    decayed_14_days = ioc_scorer.calculate_decayed_score(
        initial_score=initial,
        ioc_type="ip",
        last_seen=now - timedelta(days=14),
        current_time=now,
    )
    assert 0.45 <= decayed_14_days <= 0.55

    # After 28 days (2 half-lives), should decay to ~0.25
    decayed_28_days = ioc_scorer.calculate_decayed_score(
        initial_score=initial,
        ioc_type="ip",
        last_seen=now - timedelta(days=28),
        current_time=now,
    )
    assert 0.20 <= decayed_28_days <= 0.30

    # Expiration check
    assert ioc_scorer.is_ioc_expired(decayed_score=0.15, min_threshold=0.20) is True
    assert ioc_scorer.is_ioc_expired(decayed_score=0.85, min_threshold=0.20) is False
