/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Fixture scaffolding adapted from Girish Konda's w7-cases.test.ts at
 * girishkvs/ietf-agent-evidence@aaa3c27a88eebffda1974e9106e3d2eae7218d3e.
 * The eight original scenarios are not included here.
 *
 * Copyright (c) 2026, Girish Konda
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { type LifecycleCommit, MissionKernel } from "@mission/authorization-server";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import { createEphemeralDecisionPoint, type EvaluationRequest, type Fga } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { decodeJwt, exportJWK, generateKeyPair } from "jose";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type LoadedView,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type TokenFacts,
} from "../../../services/mcp-payments/src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "../../../services/mcp-payments/test/credential-fixtures.js";
import { permitDeadline } from "../../../services/pdp/src/permit-deadline.js";
import {
  LIFECYCLE_CHANGE_EVENT_URI,
  MissionSignalReceiver,
  signLifecycleEvent,
} from "../src/index.js";

// W7-only test adapters. Real kernel, SET verification, PDP and PEP; no HTTP,
// token exchange, live OpenFGA, tenant model, or deployed signal wiring.
const ISSUER = "https://w7-issuer.test";
const T0 = Date.parse("2026-10-23T04:00:00Z");
const S_MS = 300_000;
const L_MS = 300_000;
const EPSILON_MS = 1;
const MBA_COMMIT = "c941a738f11ea66ace2af4be5932477b21b4fce1";
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const reports: Array<Record<string, unknown>> = [];
const fixtures: CaseFixture[] = [];

type AdmissionAdapter = "none" | "cache-read-only" | "cache-revalidate" | "source-revalidate";

class DecisionGate {
  arrived = Promise.withResolvers<void>();
  release = Promise.withResolvers<void>();
}

class CaseFixture {
  nowMs = T0;
  commits: LifecycleCommit[] = [];
  workers: CaseWorker[] = [];
  trace: Array<Record<string, unknown>> = [];
  kernel!: MissionKernel;
  record!: ReturnType<MissionKernel["approve"]>;
  keys!: Awaited<ReturnType<typeof generateKeyPair>>;
  jwks!: { keys: Awaited<ReturnType<typeof exportJWK>>[] };

  constructor(readonly caseId: string) {
    fixtures.push(this);
  }

  now = () => new Date(this.nowMs);

  event(stage: string, details: Record<string, unknown> = {}) {
    this.trace.push({
      order: this.trace.length + 1,
      stage,
      logicalTime: this.now().toISOString(),
      ...details,
    });
  }

  async initialize() {
    this.keys = await generateKeyPair("ES256", { extractable: true });
    this.jwks = {
      keys: [
        { ...(await exportJWK(this.keys.publicKey)), kid: "w7-status", alg: "ES256", use: "sig" },
      ],
    };
    const policy = {
      policy_version: "w7-read-fixture",
      ceiling: [
        {
          type: "mission_resource_access" as const,
          resource: CANONICAL_RESOURCE,
          actions: ["payments:invoice.read"],
        },
      ],
    };
    this.kernel = new MissionKernel({
      issuer: ISSUER,
      policy: policy as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(policy.ceiling, ["ap-agent"], ["bob"]),
      statusKey: this.keys.privateKey,
      statusKid: "w7-status",
      now: this.now,
      onLifecycleCommit: (commit) => this.commits.push(commit),
    });
    this.record = this.kernel.approve({
      intent: {
        goal: "Read the isolated W7 invoice",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: EXPIRES_AT,
      } as never,
      proposedAuthority: policy.ceiling,
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "w7-local-approval",
    });
    this.event("mission_approved", { version: this.record.version });
  }

  addWorker(name: string, observationOnly = false) {
    const worker = new CaseWorker(this, name, observationOnly);
    this.workers.push(worker);
    return worker;
  }

  revoke() {
    this.kernel.transition(this.record.id, "revoke");
    this.event("issuer_revocation_committed", {
      state: this.commits.at(-1)?.state,
      version: this.commits.at(-1)?.version,
    });
  }

  async signedEvent(audience: string, overrides: Partial<LifecycleCommit> = {}) {
    const commit = this.commits.at(-1);
    if (!commit) throw new Error("No committed lifecycle event");
    return signLifecycleEvent(
      { ...commit, ...overrides },
      { audience, key: this.keys.privateKey, kid: "w7-status" },
    );
  }

  async deliver(worker: CaseWorker) {
    const result = await worker.receiver.verifyAndApply(await this.signedEvent(worker.audience));
    this.event("receiver_verified_and_applied", {
      worker: worker.name,
      outcome: result,
      cachedState: worker.receiver.viewState(this.record.id)?.state,
    });
    return result;
  }

  finish(details: Record<string, unknown>) {
    reports.push({ caseId: this.caseId, ...details, trace: this.trace });
  }

  close() {
    for (const worker of this.workers) {
      worker.receiver.close();
      worker.writeReservations.close();
      worker.payments.db.close();
    }
    this.kernel?.db.close();
  }
}

class CaseWorker {
  audience: string;
  receiver: MissionSignalReceiver;
  payments = new PaymentsStore();
  writeReservations = openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" });
  evidence: EvidenceStore;
  server: McpPaymentsServer;
  token: TokenFacts;
  lastRequest?: EvaluationRequest;
  lastDecision?: { decision: boolean; context: Record<string, unknown> };
  gate: DecisionGate | undefined;
  admissionAdapter: AdmissionAdapter = "none";
  advanceAtFgaMs = 0;
  lastAdmissionDecision?: { decision: boolean; context: Record<string, unknown> };

  constructor(
    readonly fixture: CaseFixture,
    readonly name: string,
    readonly observationOnly: boolean,
  ) {
    this.audience = `urn:w7:receiver:${name}`;
    this.receiver = new MissionSignalReceiver({
      issuer: ISSUER,
      audience: this.audience,
      jwks: fixture.jwks,
    });
    const decisionPoint = createEphemeralDecisionPoint({
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      emitterId: CANONICAL_RESOURCE,
      audience: CANONICAL_RESOURCE,
    });
    const keys = createEphemeralEvidenceKeys({ decisionPoint });
    this.evidence = new EvidenceStore(keys.signing, keys.resolver);
    this.payments.seed(
      [{ id: "acme", name: "W7 local vendor", status: "approved" }],
      [
        {
          id: "inv-w7",
          vendor_id: "acme",
          amount: "1.00",
          currency: "USD",
          payee_account: "fixture-only",
          status: "payable",
        },
      ],
    );
    const pep = new Pep({
      decide: async (request, options) => {
        this.lastRequest = structuredClone(request);
        const decision = await keys.decide(request, {
          ...options,
          freshnessSkewToleranceSeconds: 0,
        });
        this.lastDecision = decision;
        this.fixture.event("pdp_decision", {
          worker: name,
          permit: decision.decision,
          reason: decision.context.denial_reason,
          conditions: decision.context.conditions,
          observation: request.context.mission_state_observation,
        });
        const gate = this.gate;
        if (gate) {
          this.gate = undefined;
          gate.arrived.resolve();
          await gate.release.promise;
          this.fixture.event("held_decision_released", { worker: name });
          // TEST ADAPTER: MBA's shipped permit-use check does not consult
          // authorization state. This additional guard distinguishes a fresh
          // source lookup, a cache re-evaluation, and a mere cache reread.
          // A successful re-evaluation does not replace/extend the old permit.
          if (this.admissionAdapter !== "none") {
            const loaded =
              this.admissionAdapter === "source-revalidate"
                ? this.loadAuthoritativeView()
                : this.loadView({ id: fixture.record.id, issuer: ISSUER });
            if (!loaded) throw new Error("Admission adapter has no state");
            this.fixture.event("admission_adapter_read", {
              adapter: this.admissionAdapter,
              state: loaded.view.state,
              observation: loaded.observation,
            });
            if (this.admissionAdapter !== "cache-read-only") {
              const admissionRequest = structuredClone(request);
              admissionRequest.context.mission_state_observation = loaded.observation;
              const checked = await keys.decide(admissionRequest, {
                ...options,
                view: loaded.view,
                freshnessSkewToleranceSeconds: 0,
              });
              this.lastAdmissionDecision = checked;
              this.fixture.event("admission_adapter_pdp_decision", {
                permit: checked.decision,
                reason: checked.context.denial_reason,
              });
              if (!checked.decision) return checked;
            }
          }
        }
        return decision;
      },
      payments: this.payments,
      evidence: this.evidence,
      fga: {
        checkWithContext: async () => {
          if (this.advanceAtFgaMs !== 0) {
            const advanceMs = this.advanceAtFgaMs;
            this.advanceAtFgaMs = 0;
            fixture.nowMs += advanceMs;
            fixture.event("fga_clock_advanced", { advanceMs });
          }
          return true;
        },
      } as unknown as Fga,
      modelId: "w7-local-allowing-fga-stub",
      loadView: (reference) => this.loadView(reference),
      instanceEpoch: `w7-${name}`,
      now: fixture.now,
    });
    this.server = new McpPaymentsServer({
      pep,
      payments: this.payments,
      writeReservations: this.writeReservations,
      loadView: (reference) => this.loadView(reference),
      jwks: { keys: [] },
      keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
      issuer: ISSUER,
    });
    this.token = {
      sub: "alice",
      clientId: "ap-agent",
      clientInstanceId: "w7-subagent",
      act: {
        iss: ISSUER,
        sub: "w7-subagent",
        sub_profile: "ai_agent client_instance",
        act: { iss: ISSUER, sub: "w7-orchestrator", sub_profile: "ai_agent client_instance" },
      },
      mission: {
        id: fixture.record.id,
        issuer: ISSUER,
        authority_hash: fixture.record.authority_hash,
      },
      cnfJkt: "w7-verified-token-facts-seam",
      credentialAuthority: ALL_ACTIONS_CREDENTIAL,
    };
  }

  loadView(reference: { id: string; issuer: string }): LoadedView | undefined {
    const record = this.fixture.record;
    if (reference.id !== record.id || reference.issuer !== record.issuer) {
      return undefined;
    }
    const state = this.receiver.viewState(record.id);
    const retained = this.receiver.retainedSet(record.id);
    if (!state || !retained) {
      return undefined;
    }
    const payload = decodeJwt(retained);
    const event = (payload.events as Record<string, Record<string, unknown>>)[
      LIFECYCLE_CHANGE_EVENT_URI
    ];
    if (!event) throw new Error("Retained SET lacks the lifecycle event");
    return {
      view: {
        id: record.id,
        issuer: record.issuer,
        state: state.state,
        version: state.version,
        authority_hash: record.authority_hash,
        authority_set: record.authority_set,
        subject: record.subject,
        client_id: record.client_id,
      },
      observation: {
        state: state.state,
        version: state.version,
        // Synthetic observation-only variant exercises MBA's no-explicit-
        // valid-through API path. It preserves the source time; calling this
        // adapter later is not represented as a fresh authoritative lookup.
        mode: this.observationOnly ? "fresh" : "event_driven",
        freshness_at: event.committed_at as string,
        ...(this.observationOnly
          ? {}
          : {
              mission_status_issued_at: event.committed_at as string,
              mission_status_expires_at: state.expires_at,
            }),
      },
    };
  }

  loadAuthoritativeView(): LoadedView {
    // A real read of the in-process kernel's current SQLite state, not of the
    // receiver cache. This is a test adapter, not deployed status transport.
    const record = this.fixture.kernel.get(this.fixture.record.id);
    if (!record) throw new Error("Mission missing at authoritative source");
    return {
      view: {
        id: record.id,
        issuer: record.issuer,
        state: record.state,
        version: record.version,
        authority_hash: record.authority_hash,
        authority_set: record.authority_set,
        subject: record.subject,
        client_id: record.client_id,
      },
      observation: {
        state: record.state,
        version: record.version,
        mode: "fresh",
        freshness_at: this.fixture.now().toISOString(),
      },
    };
  }

  holdNextDecision() {
    const gate = new DecisionGate();
    this.gate = gate;
    return gate;
  }

  async read() {
    const result = await this.server.callReadTool(
      "get_invoice",
      { invoice_id: "inv-w7" },
      this.token,
    );
    this.fixture.event("tool_call_returned", { worker: this.name, result });
    return result;
  }
}

afterEach(() => {
  for (const fixture of fixtures.splice(0)) {
    if (!reports.some((r) => r.caseId === fixture.caseId)) {
      fixture.finish({
        caseIncomplete: true,
        lastDecisions: fixture.workers.map((w) => w.lastDecision),
      });
    }
    fixture.close();
  }
});

afterAll(() => {
  const directory = process.env.W7_BOUNDARY_RESULT_DIRECTORY;
  if (!directory) throw new Error("W7 boundary result directory is required");
  writeFileSync(
    join(directory, "boundary-traces.json"),
    `${JSON.stringify(
      {
        targetMbaCommit: MBA_COMMIT,
        clock: {
          unit: "integer epoch milliseconds",
          epsilonMs: EPSILON_MS,
          injectedClockSkewMs: 0,
          freshnessFutureSkewToleranceMs: 0,
          ageOrPermitExpiryGraceMs: 0,
          measuredWallClockAccuracy: "not measured",
        },
        sMs: S_MS,
        lMs: L_MS,
        scope:
          "real MBA components in one process; synthetic adapters; not a distributed deployment",
        cases: reports,
      },
      null,
      2,
    )}\n`,
  );
});

function validUntil(worker: CaseWorker): number {
  const conditions = worker.lastDecision?.context.conditions as
    | { valid_until?: string }
    | undefined;
  expect(typeof conditions?.valid_until).toBe("string");
  if (typeof conditions?.valid_until !== "string") throw new Error("No permit deadline");
  const deadline = Date.parse(conditions.valid_until);
  expect(Number.isFinite(deadline)).toBe(true);
  return deadline;
}

function expectOriginalAsOf(worker: CaseWorker) {
  expect(worker.lastRequest?.context.mission_state_observation?.freshness_at).toBe(
    new Date(T0).toISOString(),
  );
}

async function setup(caseId: string, observationOnly = false) {
  const fixture = new CaseFixture(caseId);
  await fixture.initialize();
  const worker = fixture.addWorker("A", observationOnly);
  expect((await fixture.deliver(worker)).status).toBe("applied");
  return { fixture, worker };
}

// Always release and settle a held call even when an assertion fails. Each
// boundary attempt uses a fresh fixture, never a reused/consumed permit.
async function heldRead(worker: CaseWorker, atGate: () => void | Promise<void>) {
  const gate = worker.holdNextDecision();
  const pending = worker.read();
  try {
    await Promise.race([
      gate.arrived.promise,
      pending.then(() => {
        throw new Error("Read returned before the PDP gate");
      }),
    ]);
    await atGate();
    gate.release.resolve();
    return await pending;
  } finally {
    gate.release.resolve();
    await pending.catch(() => undefined);
  }
}

const OFFSETS = [-EPSILON_MS, 0, EPSILON_MS] as const;

describe("W7 extension: exact time boundaries of the pinned MBA components", () => {
  for (const delta of OFFSETS) {
    it(`B1 state-age issuance, explicit state expiry: S${delta >= 0 ? "+" : ""}${delta}ms`, async () => {
      const { fixture, worker } = await setup(`B1-issue-${delta}`);
      fixture.nowMs = T0 + S_MS + delta;
      const result = await worker.read();
      expectOriginalAsOf(worker);
      const permitted = delta <= 0;
      expect(worker.lastDecision?.decision).toBe(permitted);
      expect(result.ok).toBe(permitted);
      if (permitted) {
        expect(validUntil(worker)).toBe(fixture.nowMs + L_MS);
      } else {
        expect(result.denial_reason).toBe("stale_state");
        expect(result.result).toBeUndefined();
      }
      fixture.finish({
        stage: "issuance",
        ageMs: S_MS + delta,
        stateExpiry: EXPIRES_AT,
        expectedPermit: permitted,
        decision: worker.lastDecision,
        outcome: result,
      });
    });
  }

  for (const delta of OFFSETS) {
    it(`B2 observation-only issuance and deadline: S${delta >= 0 ? "+" : ""}${delta}ms`, async () => {
      const { fixture, worker } = await setup(`B2-observation-only-${delta}`, true);
      fixture.nowMs = T0 + S_MS + delta;
      const deadline = permitDeadline({
        nowMs: fixture.nowMs,
        permitTtlSeconds: L_MS / 1000,
        stalenessBound: { kind: "bounded", seconds: S_MS / 1000 },
        stateObservedAtMs: T0,
      });
      const result = await worker.read();
      expectOriginalAsOf(worker);
      const permitted = delta < 0;
      expect(worker.lastDecision?.decision).toBe(permitted);
      expect(result.ok).toBe(permitted);
      if (permitted) {
        expect(deadline).toMatchObject({
          kind: "bounded",
          source: "state_view",
          validUntilMs: T0 + S_MS,
        });
        expect(validUntil(worker)).toBe(T0 + S_MS);
      } else {
        expect(deadline).toEqual({ kind: "elapsed", source: "state_view" });
        expect(result.denial_reason).toBe("stale_state");
      }
      fixture.finish({
        stage: "issuance_without_explicit_state_expiry",
        ageMs: S_MS + delta,
        expectedPermit: permitted,
        // At equality B1 isolates acceptance by the age gate; B2 calls the
        // real deadline helper separately to identify the later refusal.
        deadlineHelper: deadline,
        decision: worker.lastDecision,
        outcome: result,
      });
    });
  }

  for (const delta of OFFSETS) {
    it(`B3 permit admission: valid_until${delta >= 0 ? "+" : ""}${delta}ms`, async () => {
      const { fixture, worker } = await setup(`B3-use-${delta}`);
      let deadline = 0;
      const result = await heldRead(worker, () => {
        expect(worker.lastDecision?.decision).toBe(true);
        deadline = validUntil(worker);
        expect(deadline).toBe(T0 + L_MS);
        fixture.nowMs = deadline + delta;
      });
      expect(result.ok).toBe(delta <= 0);
      if (delta > 0) {
        expect(result.refusal_reason).toBe("permit_expired");
        expect(result.result).toBeUndefined();
      }
      fixture.finish({
        stage: "permit_admission",
        validUntilMs: deadline,
        admissionAtMs: fixture.nowMs,
        expectedAdmission: delta <= 0,
        outcome: result,
      });
    });
  }

  for (const issueDelta of [-EPSILON_MS, 0] as const) {
    for (const envelopeDelta of OFFSETS) {
      it(`B4 combined original as-of + S + L: issue S${issueDelta}, admit S+L${envelopeDelta}`, async () => {
        const { fixture, worker } = await setup(`B4-combined-${issueDelta}-${envelopeDelta}`);
        fixture.nowMs = T0 + EPSILON_MS;
        fixture.revoke(); // Withhold this event from the receiver.
        const revokedAtMs = fixture.nowMs;
        fixture.nowMs = T0 + S_MS + issueDelta;
        const issueAtMs = fixture.nowMs;
        let deadline = 0;
        const result = await heldRead(worker, () => {
          expect(worker.lastDecision?.decision).toBe(true);
          expectOriginalAsOf(worker);
          expect(worker.receiver.viewState(fixture.record.id)?.state).toBe("active");
          expect(fixture.kernel.get(fixture.record.id)?.state).toBe("terminated");
          deadline = validUntil(worker);
          expect(deadline).toBe(issueAtMs + L_MS);
          fixture.nowMs = T0 + S_MS + L_MS + envelopeDelta;
        });
        const permitted = envelopeDelta <= issueDelta;
        expect(result.ok).toBe(permitted);
        if (!permitted) {
          expect(result.refusal_reason).toBe("permit_expired");
          expect(result.result).toBeUndefined();
        }
        expectOriginalAsOf(worker);
        fixture.finish({
          stage: "combined_envelope",
          originalAsOfMs: T0,
          revokedAtMs,
          issueAtMs,
          validUntilMs: deadline,
          admissionAtMs: fixture.nowMs,
          elapsedSinceAsOfMs: fixture.nowMs - T0,
          elapsedSinceRevocationMs: fixture.nowMs - revokedAtMs,
          expectedAdmission: permitted,
          outcome: result,
        });
      });
    }
  }

  for (const adapter of ["cache-revalidate", "source-revalidate"] as const) {
    it(`B5 admission recheck within S distinguishes source from cache: ${adapter}`, async () => {
      const { fixture, worker } = await setup(`B5-${adapter}`);
      fixture.nowMs = T0 + 100_000;
      worker.admissionAdapter = adapter;
      const result = await heldRead(worker, () => {
        expect(worker.lastDecision?.decision).toBe(true);
        fixture.nowMs = T0 + 125_000;
        fixture.revoke(); // No signal delivery to the active receiver cache.
        fixture.nowMs = T0 + 150_000;
        expect(validUntil(worker)).toBe(T0 + 400_000);
      });
      const permitted = adapter === "cache-revalidate";
      expect(result.ok).toBe(permitted);
      expect(worker.lastAdmissionDecision?.decision).toBe(permitted);
      if (!permitted) expect(result.denial_reason).toBe("mission_inactive");
      expectOriginalAsOf(worker);
      fixture.finish({
        stage: "test_adapter_admission_recheck",
        adapter,
        expectedAdmission: permitted,
        originalDecision: worker.lastDecision,
        admissionDecision: worker.lastAdmissionDecision,
        outcome: result,
      });
    });
  }

  for (const adapter of ["cache-read-only", "cache-revalidate"] as const) {
    it(`B6 admission past S with an unexpired permit: ${adapter}`, async () => {
      const { fixture, worker } = await setup(`B6-${adapter}`);
      fixture.nowMs = T0 + EPSILON_MS;
      fixture.revoke();
      fixture.nowMs = T0 + S_MS - EPSILON_MS;
      worker.admissionAdapter = adapter;
      const result = await heldRead(worker, () => {
        expect(worker.lastDecision?.decision).toBe(true);
        expect(validUntil(worker)).toBe(T0 + S_MS - EPSILON_MS + L_MS);
        fixture.nowMs = T0 + S_MS + EPSILON_MS;
        expect(fixture.nowMs).toBeLessThan(validUntil(worker));
      });
      const permitted = adapter === "cache-read-only";
      expect(result.ok).toBe(permitted);
      if (!permitted) {
        expect(result.denial_reason).toBe("stale_state");
        expect(worker.lastAdmissionDecision?.decision).toBe(false);
      } else {
        expect(worker.lastAdmissionDecision).toBeUndefined();
      }
      expectOriginalAsOf(worker);
      fixture.finish({
        stage: "test_adapter_cache_age",
        adapter,
        expectedAdmission: permitted,
        originalDecision: worker.lastDecision,
        admissionDecision: worker.lastAdmissionDecision,
        outcome: result,
      });
    });
  }

  it("B7 observation-only control: the final state deadline refuses an FGA crossing of S", async () => {
    const { fixture, worker } = await setup("B7-observation-only-delay-control", true);
    fixture.nowMs = T0 + S_MS - EPSILON_MS;
    const evaluationStartedAtMs = fixture.nowMs;
    worker.advanceAtFgaMs = 2 * EPSILON_MS;
    const result = await worker.read();
    expectOriginalAsOf(worker);
    expect(fixture.nowMs).toBe(T0 + S_MS + EPSILON_MS);
    expect(worker.lastDecision?.decision).toBe(false);
    expect(result.ok).toBe(false);
    expect(result.denial_reason).toBe("stale_state");
    fixture.finish({
      stage: "observation_only_deadline_after_FGA",
      evaluationStartedAtMs,
      decisionCompletedAtMs: fixture.nowMs,
      sourceAgeAtCompletionMs: fixture.nowMs - T0,
      decision: worker.lastDecision,
      outcome: result,
    });
  });

  it("B7 characterization: an awaited FGA step can cross S after the age check", async () => {
    const { fixture, worker } = await setup("B7-age-check-to-issuance-gap");
    fixture.nowMs = T0 + S_MS - EPSILON_MS;
    const evaluationStartedAtMs = fixture.nowMs;
    worker.advanceAtFgaMs = 2 * EPSILON_MS;
    const result = await worker.read();
    expectOriginalAsOf(worker);
    expect(fixture.nowMs).toBe(T0 + S_MS + EPSILON_MS);
    expect(worker.lastDecision?.decision).toBe(true);
    expect(result.ok).toBe(true);
    expect(validUntil(worker)).toBe(T0 + S_MS + EPSILON_MS + L_MS);
    fixture.finish({
      stage: "characterization_not_S_at_issuance_enforcement",
      evaluationStartedAtMs,
      decisionCompletedAtMs: fixture.nowMs,
      sourceAgeAtCompletionMs: fixture.nowMs - T0,
      validUntilMs: validUntil(worker),
      decision: worker.lastDecision,
      outcome: result,
    });
  });
});
