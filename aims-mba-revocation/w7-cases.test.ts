import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { decodeJwt, exportJWK, generateKeyPair } from "jose";
import { type LifecycleCommit, MissionKernel } from "@mission/authorization-server";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";
import { createEphemeralDecisionPoint, type EvaluationRequest, type Fga, type MissionView } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type LoadedView,
  type TokenFacts,
} from "../../../services/mcp-payments/src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "../../../services/mcp-payments/test/credential-fixtures.js";
import { decisionCacheKey } from "../../../services/pdp/src/projections.js";
import {
  LIFECYCLE_CHANGE_EVENT_URI,
  MissionSignalEmitter,
  MissionSignalReceiver,
  signLifecycleEvent,
} from "../src/index.js";

// W7-only test adapters. Real kernel, SET verification, PDP and PEP; no HTTP,
// token exchange, live OpenFGA, tenant model, or deployed signal wiring.
const ISSUER = "https://w7-issuer.test";
const T0 = Date.parse("2026-10-10T04:00:00Z");
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const reports: Array<Record<string, unknown>> = [];
const fixtures: CaseFixture[] = [];

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
      keys: [{ ...(await exportJWK(this.keys.publicKey)), kid: "w7-status", alg: "ES256", use: "sig" }],
    };
    const policy = {
      policy_version: "w7-read-fixture",
      ceiling: [{
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read"],
      }],
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

  addWorker(name: string) {
    const worker = new CaseWorker(this, name);
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
      worker.writeReservations.close();
      worker.payments.db.close();
    }
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
  gate?: DecisionGate;

  constructor(readonly fixture: CaseFixture, readonly name: string) {
    this.audience = `urn:w7:receiver:${name}`;
    this.receiver = new MissionSignalReceiver({
      issuer: ISSUER,
      audience: this.audience,
      jwks: fixture.jwks,
    });
    const decisionPoint = createEphemeralDecisionPoint({
      emitterId: CANONICAL_RESOURCE,
      audience: CANONICAL_RESOURCE,
    });
    const keys = createEphemeralEvidenceKeys({ decisionPoint });
    this.evidence = new EvidenceStore(keys.signing, keys.resolver);
    this.payments.seed(
      [{ id: "acme", name: "W7 local vendor", status: "approved" }],
      [{ id: "inv-w7", vendor_id: "acme", amount: "1.00", currency: "USD", payee_account: "fixture-only", status: "payable" }],
    );
    const pep = new Pep({
      decide: async (request, options) => {
        this.lastRequest = structuredClone(request);
        const decision = await keys.decide(request, options);
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
        }
        return decision;
      },
      payments: this.payments,
      evidence: this.evidence,
      fga: { checkWithContext: async () => true } as unknown as Fga,
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
      mission: { id: fixture.record.id, issuer: ISSUER, authority_hash: fixture.record.authority_hash },
      cnfJkt: "w7-verified-token-facts-seam",
      credentialAuthority: ALL_ACTIONS_CREDENTIAL,
    };
  }

  loadView(reference: { id: string; issuer: string }): LoadedView | undefined {
    const record = this.fixture.record;
    if (reference.id !== record.id ||
        reference.issuer !== record.issuer) {
      return undefined;
    }
    const state = this.receiver.viewState(record.id);
    const retained = this.receiver.retainedSet(record.id);
    if (!state ||
        !retained) {
      return undefined;
    }
    const payload = decodeJwt(retained);
    const event = (payload.events as Record<string, Record<string, unknown>>)[LIFECYCLE_CHANGE_EVENT_URI]!;
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
        mode: "event_driven",
        freshness_at: event.committed_at as string,
        mission_status_issued_at: event.committed_at as string,
        mission_status_expires_at: state.expires_at,
      },
    };
  }

  holdNextDecision() {
    const gate = new DecisionGate();
    this.gate = gate;
    return gate;
  }

  async read() {
    const result = await this.server.callReadTool("get_invoice", { invoice_id: "inv-w7" }, this.token);
    this.fixture.event("tool_call_returned", { worker: this.name, result });
    return result;
  }
}

afterEach(() => {
  for (const fixture of fixtures.splice(0)) fixture.close();
});

afterAll(() => {
  const directory = process.env.W7_RESULT_DIRECTORY;
  if (!directory) throw new Error("W7 result directory is required");
  writeFileSync(join(directory, "case-traces.json"), JSON.stringify(reports, null, 2) + "\n");
});

describe("W7: bounded probes of the pinned implementation", () => {
  it("C1-control: a revocation applied before the next delegated call denies it", async () => {
    const fixture = new CaseFixture("C1-control");
    await fixture.initialize();
    const worker = fixture.addWorker("A");
    await fixture.deliver(worker);
    expect((await worker.read()).ok).toBe(true);
    fixture.revoke();
    await fixture.deliver(worker);
    const denied = await worker.read();
    expect(denied.ok).toBe(false);
    expect(denied.denial_reason).toBe("mission_inactive");
    fixture.finish({ outcome: denied });
  });

  it("C1-in-flight: a permit computed before receipt can still release a read after the terminal event", async () => {
    const fixture = new CaseFixture("C1-in-flight");
    await fixture.initialize();
    const worker = fixture.addWorker("A");
    await fixture.deliver(worker);
    const gate = worker.holdNextDecision();
    const pending = worker.read();
    await gate.arrived.promise;
    expect(worker.lastDecision?.decision).toBe(true);
    fixture.revoke();
    await fixture.deliver(worker);
    expect(worker.receiver.viewState(fixture.record.id)?.state).toBe("terminated");
    gate.release.resolve();
    const admitted = await pending;
    expect(admitted.ok).toBe(true);
    expect(admitted.result).toMatchObject({ id: "inv-w7" });
    const next = await worker.read();
    expect(next.denial_reason).toBe("mission_inactive");
    fixture.finish({ heldCall: admitted, nextCall: next, cancellationClaim: "not demonstrated" });
  });

  it("C1-expiry-control: the held permit cannot release the result after its validity ends", async () => {
    const fixture = new CaseFixture("C1-expiry-control");
    await fixture.initialize();
    const worker = fixture.addWorker("A");
    await fixture.deliver(worker);
    const gate = worker.holdNextDecision();
    const pending = worker.read();
    await gate.arrived.promise;
    expect(worker.lastDecision?.decision).toBe(true);
    fixture.nowMs += 301_000;
    fixture.revoke();
    await fixture.deliver(worker);
    gate.release.resolve();
    const result = await pending;
    expect(result.ok).toBe(false);
    expect(result.refusal_reason).toBe("permit_expired");
    expect(result.result).toBeUndefined();
    fixture.finish({ outcome: result, elapsedLogicalSeconds: 301 });
  });

  it("C2-workers: receipt at A does not invalidate B; old source time bounds B until its own receipt", async () => {
    const fixture = new CaseFixture("C2-workers");
    await fixture.initialize();
    const a = fixture.addWorker("A");
    const b = fixture.addWorker("B");
    await fixture.deliver(a);
    await fixture.deliver(b);
    expect((await a.read()).ok).toBe(true);
    expect((await b.read()).ok).toBe(true);
    fixture.revoke();
    await fixture.deliver(a);
    const aAfter = await a.read();
    const bBeforeReceipt = await b.read();
    expect(aAfter.denial_reason).toBe("mission_inactive");
    expect(bBeforeReceipt.ok).toBe(true);
    fixture.nowMs += 301_000;
    const bStale = await b.read();
    expect(bStale.denial_reason).toBe("stale_state");
    expect(b.lastRequest?.context.mission_state_observation?.freshness_at).toBe(new Date(T0).toISOString());
    await fixture.deliver(b);
    const bAfterReceipt = await b.read();
    expect(bAfterReceipt.denial_reason).toBe("mission_inactive");
    fixture.finish({
      aAfterReceipt: aAfter,
      bBeforeReceipt,
      bAfter301Seconds: bStale,
      bAfterReceipt,
      topology: "two receiver and PEP instances in one process; not distributed worker conformance",
    });
  });

  it("C2-missing: an unpopulated receiver cache produces no invented status observation", async () => {
    const fixture = new CaseFixture("C2-missing");
    await fixture.initialize();
    const worker = fixture.addWorker("A");
    const result = await worker.read();
    expect(result.ok).toBe(false);
    expect(result.refusal_reason).toBe("unknown_mission");
    expect(worker.lastRequest).toBeUndefined();
    fixture.finish({ outcome: result, pdpObservation: "none: the PEP did not establish a view" });
  });

  it("C2-issuer: a same-id foreign-issuer event is refused and does not replace local state", async () => {
    const fixture = new CaseFixture("C2-issuer");
    await fixture.initialize();
    const local = fixture.addWorker("A");
    await fixture.deliver(local);
    const foreignIssuer = "https://w7-other-issuer.test";
    const foreign = new MissionSignalReceiver({
      issuer: foreignIssuer,
      audience: local.audience,
      jwks: fixture.jwks,
    });
    const active = await fixture.signedEvent(local.audience, { issuer: foreignIssuer });
    expect((await foreign.verifyAndApply(active)).status).toBe("applied");
    fixture.revoke();
    const foreignRevocation = await fixture.signedEvent(local.audience, { issuer: foreignIssuer });
    const localRefusal = await local.receiver.verifyAndApply(foreignRevocation);
    const foreignApplied = await foreign.verifyAndApply(foreignRevocation);
    expect(localRefusal).toEqual({ status: "refused", reason: "issuer" });
    expect(foreignApplied.status).toBe("applied");
    expect(local.receiver.viewState(fixture.record.id)?.state).toBe("active");
    expect(foreign.viewState(fixture.record.id)?.state).toBe("terminated");
    fixture.finish({
      localRefusal,
      localState: local.receiver.viewState(fixture.record.id),
      foreignState: foreign.viewState(fixture.record.id),
      tenantClaim: "none: different issuer namespaces are not same-issuer tenant isolation",
    });
  });

  it("C2-receipt: outbox acknowledgement is not proof of verification or enforcement", async () => {
    const fixture = new CaseFixture("C2-receipt");
    await fixture.initialize();
    const audience = "urn:w7:wrong-key-receiver";
    const wrongKeys = await generateKeyPair("ES256", { extractable: true });
    const receiver = new MissionSignalReceiver({
      issuer: ISSUER,
      audience,
      jwks: { keys: [{ ...(await exportJWK(wrongKeys.publicKey)), kid: "w7-status", alg: "ES256" }] },
    });
    const emitter = new MissionSignalEmitter({
      key: fixture.keys.privateKey,
      kid: "w7-status",
      consumers: [{ audience }],
      now: fixture.now,
    });
    let receiverResult: unknown;
    emitter.onDeliver(audience, async (set) => {
      receiverResult = await receiver.verifyAndApply(set);
      return receiverResult;
    });
    try {
      emitter.onCommit(fixture.commits.at(-1)!);
      await emitter.drain();
      expect(receiverResult).toEqual({ status: "refused", reason: "signature" });
      expect(emitter.pending()).toBe(0);
      expect(receiver.viewState(fixture.record.id)).toBeUndefined();
      fixture.finish({ receiverResult, pendingDeliveryJobs: emitter.pending(), appliedState: "none" });
    } finally {
      emitter.close();
    }
  });

  it("C2-cache-key: authorization identity and state version matter; later retrieval metadata does not", async () => {
    const fixture = new CaseFixture("C2-cache-key");
    await fixture.initialize();
    const worker = fixture.addWorker("A");
    await fixture.deliver(worker);
    expect((await worker.read()).ok).toBe(true);
    const request = worker.lastRequest!;
    const view = worker.loadView({ id: fixture.record.id, issuer: ISSUER })!.view;
    const model = "w7-local-allowing-fga-stub";
    const original = decisionCacheKey(request, view, model);
    const changedTime = structuredClone(request);
    changedTime.context.mission_state_observation!.freshness_at = new Date(T0 + 1000).toISOString();
    expect(decisionCacheKey(changedTime, view, model)).toBe(original);
    const foreign = structuredClone(request);
    foreign.context.mission.issuer = "https://w7-other-issuer.test";
    const otherAudience = structuredClone(request);
    otherAudience.resource.properties.audience = "https://w7-other-resource.test";
    const otherActor = structuredClone(request);
    otherActor.context.actor!.client_id = "other-client";
    const keys = {
      original,
      timeOnly: decisionCacheKey(changedTime, view, model),
      otherIssuer: decisionCacheKey(foreign, view, model),
      otherAudience: decisionCacheKey(otherAudience, view, model),
      otherActor: decisionCacheKey(otherActor, view, model),
      newerGeneration: decisionCacheKey(request, { ...view, version: view.version + 1 } as MissionView, model),
    };
    for (const name of ["otherIssuer", "otherAudience", "otherActor", "newerGeneration"] as const) {
      expect(keys[name]).not.toBe(original);
    }
    fixture.finish({ keys, freshnessLimit: "key equality is not permission to bypass freshness checks" });
  });
});
