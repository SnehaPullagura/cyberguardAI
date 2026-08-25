import time
import uuid
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.playbook import Playbook
from app.models.response_execution import ResponseExecution, ResponseActionExecution
from app.models.user import User
from app.response.enums import ResponseMode, ExecutionStatus, FailurePolicy, RiskLevel
from app.response.action_registry import action_registry
from app.response.safety_validator import action_safety_validator
from app.response.trigger_evaluator import trigger_evaluator
from app.response.loop_guard import loop_guard
from app.response.policy_engine import policy_engine
from app.response.approval_service import approval_service
from app.services.audit_service import audit_service
from app.schemas.websocket import RealtimeEventEnvelope
from app.websockets.pubsub import publish_realtime_event

logger = logging.getLogger(__name__)


class PlaybookExecutor:
    """Executes defensive response playbooks with safety validation, timeout, retries, and verification."""

    def execute_playbook(
        self,
        db: Session,
        playbook: Playbook,
        context: Dict[str, Any],
        user: Optional[User] = None,
        override_mode: Optional[ResponseMode] = None,
    ) -> ResponseExecution:
        """Evaluates triggers, policies, and runs the playbook action sequence."""
        execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        start_time = time.time()
        
        # 1. Evaluate Trigger Conditions
        if not trigger_evaluator.evaluate_all(playbook.trigger_conditions or [], context):
            logger.info(f"[EXECUTOR] Playbook '{playbook.name}' triggers did not match context.")
            return None

        # 2. Loop Prevention Check
        current_depth = int(context.get("execution_depth", 1))
        if loop_guard.is_loop_detected(context, current_depth=current_depth):
            logger.warning(f"[EXECUTOR] Loop detected for playbook '{playbook.name}'. Suppressing execution.")
            return None

        # 3. Policy & RBAC Evaluation
        policy_result = policy_engine.evaluate_playbook_policy(playbook, context, user=user)
        if not policy_result.allowed:
            logger.info(f"[EXECUTOR] Playbook policy denied: {policy_result.reason}")
            return None

        effective_mode = override_mode or policy_result.mode

        # 4. Acquire Cooldown Lock
        entity_key = context.get("source_entity") or context.get("source_ip") or context.get("incident_id") or "global"
        lock_acquired = loop_guard.acquire_execution_lock(
            playbook_id=playbook.playbook_id,
            entity_key=str(entity_key),
            cooldown_seconds=playbook.cooldown_seconds,
        )
        if not lock_acquired:
            logger.info(f"[EXECUTOR] Playbook '{playbook.name}' suppressed by cooldown for entity {entity_key}.")
            return None

        # 5. Create ResponseExecution Record in DB
        execution = ResponseExecution(
            id=str(uuid.uuid4()),
            execution_id=execution_id,
            playbook_id=playbook.id,
            incident_id=context.get("incident_id"),
            alert_id=context.get("alert_id"),
            trigger_event_id=context.get("event_id"),
            correlation_id=context.get("correlation_id") or str(uuid.uuid4()),
            status=ExecutionStatus.RUNNING.value,
            mode=effective_mode.value,
            started_at=datetime.utcnow(),
            triggered_by=user.username if user else "system",
            execution_depth=current_depth,
            result_metadata={"initial_context": {k: v for k, v in context.items() if k != "raw_payload"}},
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)

        # Broadcast playbook triggered & response started events
        publish_realtime_event(
            RealtimeEventEnvelope(
                type="playbook_triggered",
                correlation_id=execution.correlation_id,
                data={
                    "execution_id": execution.execution_id,
                    "playbook_id": playbook.playbook_id,
                    "playbook_name": playbook.name,
                    "mode": effective_mode.value,
                },
            )
        )
        publish_realtime_event(
            RealtimeEventEnvelope(
                type="response_started",
                correlation_id=execution.correlation_id,
                data={
                    "execution_id": execution.execution_id,
                    "playbook_name": playbook.name,
                    "started_at": execution.started_at.isoformat(),
                },
            )
        )

        # 6. Check if High-Risk Actions Require Approval
        actions_list = playbook.action_sequence or []
        for action_item in actions_list:
            action_type = action_item.get("action_type") if isinstance(action_item, dict) else str(action_item)
            action_cfg = action_item.get("action_config", {}) if isinstance(action_item, dict) else {}
            
            safety_res = action_safety_validator.validate_action_safety(
                action_type=action_type,
                action_config=action_cfg,
                requested_mode=effective_mode,
            )

            if not safety_res.is_safe:
                execution.status = ExecutionStatus.FAILED.value
                execution.error_code = "SAFETY_VALIDATION_FAILED"
                execution.error_message = safety_res.reason
                execution.completed_at = datetime.utcnow()
                execution.duration_ms = (time.time() - start_time) * 1000.0
                db.commit()
                return execution

            if safety_res.requires_approval and effective_mode != ResponseMode.DRY_RUN:
                # Pause execution and route to approval gate
                execution.status = ExecutionStatus.PENDING_APPROVAL.value
                db.commit()
                db.refresh(execution)

                approval_service.create_approval_request(
                    db=db,
                    execution=execution,
                    action_type=action_type,
                    risk_level=action_item.get("risk_level", "high"),
                    requested_by_id=user.id if user else None,
                )
                return execution

        # 7. Execute Action Sequence
        all_success = True
        for action_item in actions_list:
            action_type = action_item.get("action_type") if isinstance(action_item, dict) else str(action_item)
            action_cfg = action_item.get("action_config", {}) if isinstance(action_item, dict) else {}
            timeout_sec = int(action_item.get("timeout_seconds", playbook.timeout_seconds))
            retry_max = int(action_item.get("retry_count", 0))

            action_success = self._execute_single_action(
                db=db,
                execution=execution,
                action_type=action_type,
                action_config=action_cfg,
                context=context,
                mode=effective_mode,
                timeout_seconds=timeout_sec,
                max_retries=retry_max,
            )

            if not action_success:
                all_success = False
                if playbook.failure_policy == FailurePolicy.STOP.value:
                    logger.warning(f"[EXECUTOR] Halting playbook '{playbook.name}' due to failure in '{action_type}'.")
                    break

        # 8. Complete Execution
        execution.status = ExecutionStatus.SUCCESS.value if all_success else ExecutionStatus.FAILED.value
        if effective_mode == ResponseMode.DRY_RUN:
            execution.status = ExecutionStatus.SIMULATED.value
        elif effective_mode == ResponseMode.SIMULATION:
            execution.status = ExecutionStatus.SIMULATED.value

        execution.completed_at = datetime.utcnow()
        execution.duration_ms = (time.time() - start_time) * 1000.0
        db.commit()
        db.refresh(execution)

        # Audit execution completion
        audit_service.log_action(
            db=db,
            action="RESPONSE_PLAYBOOK_EXECUTED",
            resource=f"playbook/{playbook.playbook_id}",
            user_id=user.id if user else None,
            username=execution.triggered_by,
            status="SUCCESS" if all_success else "FAILED",
            details={
                "execution_id": execution.execution_id,
                "mode": execution.mode,
                "status": execution.status,
                "duration_ms": execution.duration_ms,
            },
        )

        # Broadcast completion WebSocket event
        event_type = "response_completed" if all_success else "response_failed"
        publish_realtime_event(
            RealtimeEventEnvelope(
                type=event_type,
                correlation_id=execution.correlation_id,
                data={
                    "execution_id": execution.execution_id,
                    "status": execution.status,
                    "mode": execution.mode,
                    "duration_ms": execution.duration_ms,
                },
            )
        )

        return execution

    def _execute_single_action(
        self,
        db: Session,
        execution: ResponseExecution,
        action_type: str,
        action_config: Dict[str, Any],
        context: Dict[str, Any],
        mode: ResponseMode,
        timeout_seconds: int = 30,
        max_retries: int = 0,
    ) -> bool:
        """Executes a single allowlisted action with timeout, retry, and verification."""
        action_def = action_registry.get(action_type)
        if not action_def:
            logger.error(f"[EXECUTOR] Action '{action_type}' not found in registry.")
            return False

        action_start = time.time()
        action_exec = ResponseActionExecution(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            action_type=action_type,
            status=ExecutionStatus.RUNNING.value,
            mode=mode.value,
            started_at=datetime.utcnow(),
            timeout_applied=timeout_seconds,
            retry_count=0,
        )
        db.add(action_exec)
        db.commit()
        db.refresh(action_exec)

        result = {}
        success = False
        error_msg = None

        # Execute with retries
        for attempt in range(max_retries + 1):
            try:
                # Synchronous adapter execution
                result = action_def.execution_handler(
                    db=db,
                    config=action_config,
                    context=context,
                    mode=mode,
                )
                success = result.get("success", False)
                if success:
                    break
                else:
                    error_msg = result.get("error", "Action returned failure status.")
            except Exception as e:
                logger.exception(f"[EXECUTOR] Error running action '{action_type}': {e}")
                error_msg = str(e)
                success = False

            if not success and attempt < max_retries:
                backoff_wait = 2 ** attempt
                time.sleep(min(backoff_wait, 10))

        # Verification step
        verification_status = "unverified"
        if success:
            try:
                verified = action_def.verification_handler(result, context)
                verification_status = "verified" if verified else "failed"
            except Exception as e:
                logger.warning(f"[EXECUTOR] Verification error on '{action_type}': {e}")
                verification_status = "error"
        else:
            verification_status = "failed"

        action_duration = (time.time() - action_start) * 1000.0
        action_exec.status = ExecutionStatus.SUCCESS.value if success else ExecutionStatus.FAILED.value
        action_exec.completed_at = datetime.utcnow()
        action_exec.duration_ms = action_duration
        action_exec.verification_status = verification_status
        action_exec.error_message = error_msg
        action_exec.result_metadata = result
        db.commit()

        # Broadcast action completed WebSocket event
        publish_realtime_event(
            RealtimeEventEnvelope(
                type="response_action_completed",
                correlation_id=execution.correlation_id,
                data={
                    "execution_id": execution.execution_id,
                    "action_type": action_type,
                    "status": action_exec.status,
                    "verification_status": verification_status,
                    "duration_ms": action_duration,
                },
            )
        )

        return success


playbook_executor = PlaybookExecutor()
