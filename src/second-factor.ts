import { addSeconds } from "./clock.js";
import type { SecondFactorMethod, StepUpMethod } from "./config.js";
import type { Context } from "./context.js";
import type { SessionRecord } from "./storage/types.js";

/**
 * The second factors the account has, active only. `exclude` leaves out a factor that is
 * being added, so the change can check its own grant again after the write.
 */
export async function enrolledSecondFactors(
  ctx: Context,
  accountId: string,
  exclude: { passkeyId?: string; totpId?: string } = {},
): Promise<SecondFactorMethod[]> {
  const passkeys = (await ctx.store.credentials.listByAccount(accountId)).filter(
    (c) => c.id !== exclude.passkeyId,
  );
  const totp = await ctx.store.totp.findActive(accountId);
  const methods: SecondFactorMethod[] = [];
  if (passkeys.length > 0) methods.push("passkey");
  if (totp && totp.id !== exclude.totpId) methods.push("totp");
  return methods;
}

/**
 * The step-up that allows adding or removing a second factor: a step-up with the strongest
 * factor the account has (passkey, then TOTP). With no second factor, any fresh step-up
 * (`null`). So a factor can never be changed with less than the factors it protects.
 */
export function factorChangeStepUp(enrolled: SecondFactorMethod[]): StepUpMethod[] | null {
  if (enrolled.includes("passkey")) return ["passkey"];
  if (enrolled.includes("totp")) return ["totp"];
  return null;
}

/** True if the session has a step-up within the validity window by one of `methods`. */
export function hasFreshStepUp(
  ctx: Context,
  record: SessionRecord,
  methods: StepUpMethod[] | null,
): boolean {
  const stepUp = record.stepUp;
  if (!stepUp) return false;
  if (methods !== null && !methods.includes(stepUp.method)) return false;
  return (
    ctx.clock.now().getTime() < addSeconds(stepUp.at, ctx.config.stepUp.validitySeconds).getTime()
  );
}
