import { z } from "zod";

const MAX_INPUT_LENGTH = 320;

const emailSchema = z.string().trim().min(3).max(254).email();

/** Thrown for an input that is not a plausible e-mail address. */
export class InvalidEmailError extends TypeError {
  constructor() {
    super("invalid e-mail address");
    this.name = "InvalidEmailError";
  }
}

/**
 * Normalizes an e-mail address for storage and comparison: Unicode NFC, trimmed,
 * lowercase. Throws `InvalidEmailError` for a malformed address. The result does not depend
 * on whether an account exists for the address.
 */
export function normalizeEmail(input: unknown): string {
  // Reject non-strings and oversized input before any parsing work.
  if (typeof input !== "string" || input.length > MAX_INPUT_LENGTH) throw new InvalidEmailError();
  const parsed = emailSchema.safeParse(input.normalize("NFC"));
  if (!parsed.success) throw new InvalidEmailError();
  return parsed.data.toLowerCase();
}
