/**
 * PostgreSQL tests. They run only when DATABASE_URL points to a throwaway database:
 *
 *   DATABASE_URL=postgres://user:pass@localhost:5432/scratch pnpm test:postgres
 *
 * Each run creates its own schema and drops it at the end.
 */
import { randomBytes } from "node:crypto";
import { Kysely, PostgresDialect, sql } from "kysely";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createPostgresStore,
  migrateIdentkit,
  type IdentkitDatabase,
} from "../../src/postgres/index.js";
import type { IdentkitStore } from "../../src/storage/types.js";
import { mfaPolicy, otherCode, setup, STEP, testConfig } from "../helpers.js";
import { runStoreContract } from "../store-contract.js";

const url = process.env["DATABASE_URL"];
const schema = `identkit_test_${randomBytes(6).toString("hex")}`;

let db: Kysely<IdentkitDatabase> | undefined;
let store: IdentkitStore | undefined;

function requireStore(): IdentkitStore {
  if (!store) throw new Error("store not initialised");
  return store;
}

describe.skipIf(!url)("postgresql", () => {
  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: url });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.end();
    db = new Kysely<IdentkitDatabase>({
      dialect: new PostgresDialect({
        pool: new pg.Pool({ connectionString: url, max: 10, options: `-c search_path=${schema}` }),
      }),
    });
    const applied = await migrateIdentkit(db);
    expect(applied).toEqual(["0001_initial.sql", "0002_totp.sql"]);
    expect(await migrateIdentkit(db)).toEqual([]);
    store = createPostgresStore(db);
  });

  afterAll(async () => {
    if (db) {
      await sql.raw(`DROP SCHEMA ${schema} CASCADE`).execute(db);
      await db.destroy();
    }
  });

  runStoreContract("postgresql", () => requireStore());

  it("flows: e-mail sign-in, attempt limit and single use against PostgreSQL", async () => {
    const t = setup({ store: requireStore() });
    const first = await t.codeFor("pg-person@example.org");
    const guesses = await Promise.all(
      Array.from({ length: 10 }, () =>
        t.ik.emailSignIn.verifyCode({ flowId: first.flowId, code: otherCode(first.code) }),
      ),
    );
    expect(guesses.every((g) => g.status === "failed")).toBe(true);
    expect((await requireStore().otp.findById(first.flowId))?.attempts).toBe(
      testConfig.emailOtp.maxAttemptsPerCode,
    );

    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const second = await t.codeFor("pg-person@example.org");
    const uses = await Promise.all(
      Array.from({ length: 5 }, () => t.ik.emailSignIn.verifyCode(second)),
    );
    expect(uses.filter((u) => u.status === "signed_in")).toHaveLength(1);
  });

  it("flows: passkey registration, sign-in, step-up and approval against PostgreSQL", async () => {
    const t = setup({ store: requireStore() });
    const user = await t.userWithPasskey("pg-passkey@example.org");
    const { options } = await t.ik.passkeys.startSignIn();
    const assertion = t.authenticator.assert(options);
    expect((await t.ik.passkeys.finishSignIn(assertion)).status).toBe("signed_in");
    expect((await t.ik.passkeys.finishSignIn(assertion)).status).toBe("failed");

    const stepUp = await t.ik.stepUp.startPasskey(user.token);
    if (stepUp.status !== "ok") throw new Error("denied");
    const granted = await t.ik.stepUp.finishPasskey(
      user.token,
      t.authenticator.assert(stepUp.options),
    );
    if (granted.status !== "granted") throw new Error("not granted");
    expect((await t.ik.sessions.requireStepUp(granted.token, { methods: ["passkey"] })).ok).toBe(
      true,
    );

    const payloadHash = "b".repeat(64);
    const approval = await t.ik.approvals.start({ sessionToken: granted.token, payloadHash });
    if (approval.status !== "ok" || approval.level !== "signature") throw new Error("denied");
    const response = t.authenticator.assert(approval.options);
    expect(
      (await t.ik.approvals.verify({ sessionToken: granted.token, payloadHash, response })).status,
    ).toBe("approved");
    expect(
      (await t.ik.approvals.verify({ sessionToken: granted.token, payloadHash, response })).status,
    ).toBe("failed");
  });

  it("flows: TOTP enrolment, second factor, replay and code approval against PostgreSQL", async () => {
    const t = setup({
      store: requireStore(),
      policy: { ...mfaPolicy, approvalEvidenceLevels: ["signature", "code-confirmation"] },
    });
    const user = await t.signIn("pg-totp@example.org");
    const { secret } = await t.enrolTotp(user.token);
    const row = await requireStore().totp.findActive(user.account.id);
    expect(row?.sealedSecret).not.toContain(secret);

    // Parallel step-ups with one code on five sessions: exactly one wins.
    t.clock.advanceSeconds(STEP);
    const tokens = [user.token];
    for (let i = 0; i < 4; i += 1) {
      const { flowId, code } = await t.codeFor("pg-totp@example.org");
      const pending = await t.ik.emailSignIn.verifyCode({ flowId, code });
      if (pending.status !== "second_factor_required") throw new Error(pending.status);
      t.clock.advanceSeconds(STEP);
      const done = await t.ik.totp.verifySecondFactor(pending.pendingToken, {
        code: t.totpCode(secret),
      });
      if (done.status !== "signed_in") throw new Error(done.status);
      tokens.push(done.token);
    }
    t.clock.advanceSeconds(STEP);
    const code = t.totpCode(secret);
    const results = await Promise.all(
      tokens.map((token) => t.ik.stepUp.verifyTotp(token, { code })),
    );
    expect(results.filter((r) => r.status === "granted")).toHaveLength(1);

    // A code approval consumes its step: the same code cannot approve twice.
    t.clock.advanceSeconds(STEP);
    const live = results.find((r) => r.status === "granted");
    if (live?.status !== "granted") throw new Error("no step-up");
    const payloadHash = "d".repeat(64);
    const approvalCode = t.totpCode(secret);
    const approvals = await Promise.all(
      [0, 1].map(async () => {
        const start = await t.ik.approvals.start({
          sessionToken: live.token,
          payloadHash,
          levels: ["code-confirmation"],
        });
        if (start.status !== "ok" || start.level !== "code-confirmation") {
          throw new Error("denied");
        }
        return t.ik.approvals.verify({
          sessionToken: live.token,
          payloadHash,
          approvalId: start.approvalId,
          code: approvalCode,
        });
      }),
    );
    expect(approvals.filter((a) => a.status === "approved")).toHaveLength(1);
  });

  it("flows: session timeouts and revocation against PostgreSQL", async () => {
    const t = setup({ store: requireStore() });
    const { token } = await t.signIn("pg-session@example.org");
    t.clock.advanceSeconds(testConfig.sessions.idleTimeoutSeconds - 1);
    expect(await t.ik.sessions.validate(token)).not.toBeNull();
    t.clock.advanceSeconds(testConfig.sessions.idleTimeoutSeconds);
    expect(await t.ik.sessions.validate(token)).toBeNull();
  });
});
