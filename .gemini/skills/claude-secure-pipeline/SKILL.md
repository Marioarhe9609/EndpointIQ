---
name: claude-secure-pipeline
description: >-
  Executes the 4-phase Secure Multi-Agent Development Pipeline coordinating Antigravity (Gemini 3.7) with Claude Code CLI with strict non-regression enforcement.
  Use this skill whenever a feature, module, or code task must undergo strict peer review, static security audits, multi-criteria testing gates, and regression validation.
---

# Secure Multi-Agent Pipeline (Gemini 3.7 + Claude Code) with Non-Regression Enforcement

This skill enforces a continuous 4-phase secure development lifecycle with automated Quality Gates ensuring zero regressions on existing application features using the bridge script at:
C:\Users\ASUS\.gemini\config\skills\claude-secure-pipeline\scripts\claude_gate.py

## Phase 1: Requirements & Architecture Plan (Impact & Non-Regression Analysis)
1. **Prompt Generation**: Claude Code defines the structured architectural prompt.
   `ash
   python C:\Users\ASUS\.gemini\config\skills\claude-secure-pipeline\scripts\claude_gate.py generate-prompt <requirement_file>
   `
2. **Plan Generation**: Gemini 3.7 creates implementation_plan.md, including a mandatory "Non-Regression & Backward Compatibility Strategy" section.
3. **Plan Gate**: Claude Code audits the plan and verifies preservation of existing APIs, schemas, and signatures.
   `ash
   python C:\Users\ASUS\.gemini\config\skills\claude-secure-pipeline\scripts\claude_gate.py review-plan implementation_plan.md
   `
   *Gate 1*: Stop until status: APPROVED.

## Phase 2: Implementation & SAST Audit (Backward Compatibility Check)
1. **Core Development**: Gemini 3.7 generates clean, secure code maintaining strict backward compatibility.
2. **Code Security Audit**: Claude Code reviews the code for security vulnerabilities and breaking changes.
   `ash
   python C:\Users\ASUS\.gemini\config\skills\claude-secure-pipeline\scripts\claude_gate.py audit-code <source_files>
   `
   *Gate 2*: Fix all High/Medium issues and breaking changes until status: APPROVED.

## Phase 3: Robust Testing (7-Pillar Matrix + Pre-existing Suite Validation)
1. **Pre-existing Suite Validation (Pillar 0 - Zero Regression)**:
   - Run existing test suite (python -m unittest discover -s tests). All pre-existing tests MUST pass (0 failures allowed).
2. **Test Matrix Generation**: Claude Code defines NFR test matrix (Scalability, Manageability, Efficiency, Resource Usage, HA, Security, Fault Tolerance).
   `ash
   python C:\Users\ASUS\.gemini\config\skills\claude-secure-pipeline\scripts\claude_gate.py generate-test-matrix <source_files>
   `
3. **Test Implementation**: Gemini 3.7 writes and executes the new test suite.
4. **Test Compliance Audit**: Claude Code validates consolidated results (both pre-existing suite and new tests).
   `ash
   python C:\Users\ASUS\.gemini\config\skills\claude-secure-pipeline\scripts\claude_gate.py verify-tests <test_report>
   `
   *Gate 3*: Stop until zero_regressions: true and ready_for_human_review: true.

## Phase 4: Human-in-the-Loop (HITL)
1. Present consolidated results in walkthrough.md with a Critical Smoke Test checklist (Login/2FA, Agent Ingest, Dashboard, Database).
2. Guide the user through final unit validation and End-to-End (E2E) testing.
