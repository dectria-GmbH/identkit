/**
 * Throttle keys of TOTP. A module without imports, so that the account calls and the TOTP
 * engine can both use them without importing each other.
 */
export const totpThrottleKey = (accountId: string) => `totp:${accountId}`;
export const totpEnrolmentThrottleKey = (accountId: string) => `totp-enrolment:${accountId}`;
