import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.threat_feed import ThreatFeed
from app.models.threat_intel import ThreatIoC
from app.models.stix_object import STIXObject
from app.threat_intel.taxii_client import taxii_client
from app.threat_intel.stix_parser import stix_parser, ParsedSTIXBundle
from app.threat_intel.ioc_scorer import ioc_scorer
from app.websockets.pubsub import publish_realtime_event
from app.schemas.websocket import RealtimeEventEnvelope

logger = logging.getLogger(__name__)


class ThreatFeedScheduler:
    """Orchestrates threat feed synchronizations, deduplication, confidence adjustments, and lifecycle maintenance."""

    def sync_feed(self, db: Session, feed: ThreatFeed) -> Dict[str, Any]:
        """Synchronizes an individual threat feed, ingesting and deduplicating STIX/TAXII objects."""
        logger.info(f"[FEED SYNC] Starting synchronization for feed '{feed.name}' ({feed.feed_id})...")
        feed.last_status = "syncing"
        db.commit()

        try:
            bundle: ParsedSTIXBundle
            if feed.feed_type == "taxii21" and feed.url.startswith("http"):
                bundle = taxii_client.poll_collection(
                    collection_url=feed.url,
                    api_key=feed.api_key,
                )
            else:
                # Use mock bundle for internal/demo feeds
                mock_data = taxii_client.generate_mock_taxii_bundle(feed_name=feed.name)
                bundle = stix_parser.parse_bundle(mock_data)

            # 1. Ingest STIX raw objects
            stix_created = 0
            for raw_obj in bundle.raw_objects:
                stix_id = raw_obj.get("id")
                if not stix_id:
                    continue
                existing_stix = db.query(STIXObject).filter(STIXObject.stix_id == stix_id).first()
                if not existing_stix:
                    db.add(
                        STIXObject(
                            stix_id=stix_id,
                            spec_version=raw_obj.get("spec_version", "2.1"),
                            type=raw_obj.get("type", "unknown"),
                            name=raw_obj.get("name"),
                            description=raw_obj.get("description"),
                            pattern=raw_obj.get("pattern"),
                            pattern_type=raw_obj.get("pattern_type"),
                            source_ref=raw_obj.get("source_ref"),
                            target_ref=raw_obj.get("target_ref"),
                            relationship_type=raw_obj.get("relationship_type"),
                            external_references=raw_obj.get("external_references", []),
                            stix_data=raw_obj,
                        )
                    )
                    stix_created += 1

            # 2. Ingest and deduplicate Indicators
            iocs_ingested = 0
            iocs_updated = 0
            for ind in bundle.indicators:
                val = ind["value"]
                ioc_type = ind["ioc_type"]
                existing_ioc = db.query(ThreatIoC).filter(
                    ThreatIoC.value == val,
                    ThreatIoC.ioc_type == ioc_type,
                ).first()

                comp_confidence = ioc_scorer.compute_composite_confidence(
                    base_confidence=ind["confidence"],
                    source=feed.feed_type,
                    feed_weight=feed.confidence_weight,
                )

                if existing_ioc:
                    # Update existing IoC
                    existing_ioc.sightings_count += 1
                    existing_ioc.last_seen = datetime.utcnow()
                    existing_ioc.confidence = max(existing_ioc.confidence, comp_confidence)
                    existing_ioc.decay_score = 1.0
                    existing_ioc.is_active = True
                    if ind.get("mitre_attack_id") and not existing_ioc.mitre_attack_id:
                        existing_ioc.mitre_attack_id = ind["mitre_attack_id"]
                    iocs_updated += 1
                else:
                    new_ioc = ThreatIoC(
                        ioc_type=ioc_type,
                        value=val,
                        threat_type=ind["threat_type"],
                        confidence=comp_confidence,
                        source=f"feed:{feed.feed_id}",
                        description=ind.get("description"),
                        stix_id=ind.get("stix_id"),
                        mitre_attack_id=ind.get("mitre_attack_id"),
                        tags=ind.get("tags", []),
                        is_active=True,
                        sightings_count=1,
                    )
                    db.add(new_ioc)
                    iocs_ingested += 1

            # Update feed metadata
            feed.last_sync = datetime.utcnow()
            feed.last_status = "healthy"
            feed.last_error = None
            feed.ioc_count = (feed.ioc_count or 0) + iocs_ingested
            db.commit()

            logger.info(f"[FEED SYNC] Successfully synced '{feed.name}': +{iocs_ingested} new, ~{iocs_updated} updated.")

            # Broadcast WebSocket notification
            publish_realtime_event(
                RealtimeEventEnvelope(
                    type="threat_feed_synced",
                    data={
                        "feed_id": feed.feed_id,
                        "name": feed.name,
                        "new_iocs": iocs_ingested,
                        "updated_iocs": iocs_updated,
                        "stix_objects": stix_created,
                        "status": "healthy",
                    },
                )
            )

            return {
                "feed_id": feed.feed_id,
                "status": "healthy",
                "new_iocs": iocs_ingested,
                "updated_iocs": iocs_updated,
                "stix_objects_created": stix_created,
            }

        except Exception as e:
            logger.error(f"[FEED SYNC] Error synchronizing feed '{feed.name}': {e}", exc_info=True)
            feed.last_status = "error"
            feed.last_error = str(e)
            db.commit()
            return {"feed_id": feed.feed_id, "status": "error", "error": str(e)}

    def prune_expired_iocs(self, db: Session) -> int:
        """Evaluates all active IoCs for time decay and deactivates expired ones."""
        active_iocs = db.query(ThreatIoC).filter(ThreatIoC.is_active == True).all()
        pruned_count = 0

        for ioc in active_iocs:
            decayed = ioc_scorer.calculate_decayed_score(
                initial_score=ioc.confidence,
                ioc_type=ioc.ioc_type,
                last_seen=ioc.last_seen or ioc.created_at,
            )
            ioc.decay_score = decayed

            if ioc_scorer.is_ioc_expired(decayed, ioc.expires_at):
                ioc.is_active = False
                pruned_count += 1

        db.commit()
        logger.info(f"[FEED MAINTENANCE] Pruned/deactivated {pruned_count} decayed or expired IoCs.")
        return pruned_count


feed_scheduler = ThreatFeedScheduler()
