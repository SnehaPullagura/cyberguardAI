# Response Engine Architecture

## Overview
The CyberGuard AI Automated Playbook & Response Engine is a defensive automation system decoupled from detection mechanisms. It converts validated alerts and incidents into controlled, allowlisted security responses.

## Architecture Pipeline
```
                  DETECTION / ML
                       ↓
                  RISK ENGINE
                       ↓
                 ALERT / INCIDENT
                       ↓
              RESPONSE DECISION
                       ↓
               TRIGGER EVALUATOR
                       ↓
              LOOP PREVENTION
                       ↓
                POLICY + RBAC
                       ↓
             ALLOWLISTED ACTION
                       ↓
              ACTION SAFETY
                       ↓
              ┌────────┴────────┐
              │                 │
         LOW/MEDIUM        HIGH/CRITICAL
              │                 │
           DRY_RUN         APPROVAL GATE
              │                 │
              │          APPROVE / REJECT
              │                 │
              │          RE-AUTHORIZATION
              │                 │
              └────────┬────────┘
                       ↓
                EXECUTION ENGINE
                       ↓
                 TIMEOUT/RETRY
                       ↓
                  VERIFICATION
                       ↓
             RESPONSE EXECUTION DB
                       ↓
                  AUDIT SERVICE
                       ↓
                REDIS PUB/SUB
                       ↓
                LIVE DASHBOARD
```

## Key Invariants
1. **Decoupled Engine**: Detection determines *what happened*; Risk scoring determines *how serious it is*; Response Engine determines *whether and how* to respond.
2. **Strict Allowlisting**: Only actions registered in `ActionRegistry` can ever execute. Arbitrary command execution (`subprocess`, `eval`, `exec`, shell) is strictly prohibited.
3. **Safe Response Modes**: Default is `DRY_RUN`. Transition to `SIMULATION` or `AUTHORIZED_EXECUTION` requires explicit policy configuration and user authorization.
4. **Approval Gate**: HIGH/CRITICAL actions require human authorization with single-use decisions and strict self-approval prevention.
5. **Loop Prevention & Idempotency**: Redis-backed distributed cooldown locks and provenance tracking prevent recursive reaction loops.
