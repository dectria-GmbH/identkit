/**
 * Values produced by identkit 0.1.1 (node:crypto). Later versions must still match them:
 * stored digests and sealed secrets survive an upgrade. Do not regenerate.
 */
export const HASH_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
export const SEAL_KEY_K1_HEX = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0";
export const SEAL_KEY_OLD_HEX = "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9";

/** [purpose, value, digest] for createHmacHasher(HASH_KEY). */
export const DIGESTS: [string, string, string][] = [
  ["otp-code", "", "a8fc47925af082856826904e4592e6a55330d672c1c6a661cdb40dcf94472ce2"],
  ["otp-code", "123456", "474e39cd892514d1d5543260d34c42b4b109b6f8ae52276864762fd66b000cbb"],
  [
    "otp-code",
    "person@example.org",
    "32cf4b24bb7e02b5b3b3f4659de07b72c10456fc6724bcf96913dfc93544006f",
  ],
  [
    "otp-code",
    "Grüße 🔑 \u0000 end",
    "12e0f873ea614cf51fa1c608fa1f38d47750105b28e7549d51157c26b22968f9",
  ],
  [
    "otp-code",
    "lone \ud800 surrogate",
    "1d11389348b663273e9642261a8855882a3f3a46f04c4cd9335bd22c7aa52e01",
  ],
  ["address", "", "8151ccc1fe67e1f19f80c9eb5a8612d8d0ad46f2e7387e5c62505a2a640e1d65"],
  ["address", "123456", "08cef52594aa44bec0e7b98a49f2fb4d08f86723816d907c2b2881a3670dd6fa"],
  [
    "address",
    "person@example.org",
    "a306732e177a3b6b9e6bd20c5eab3edfe485af9798d84e9e2b13ce6a85aaf7ce",
  ],
  [
    "address",
    "Grüße 🔑 \u0000 end",
    "09376ba1cc0536b61c9fe332792712101c330ec0fc8dfdbec193e34a48e05454",
  ],
  [
    "address",
    "lone \ud800 surrogate",
    "286c325e8a2d62c6e6c4cd443c4dcc51bfcb305a9ec77e7e1fcf263c25d479d5",
  ],
  ["session-token", "", "1b5ba51f85df6ab6ee0fa690acd374d3842e8605990e23e7cca00150ad806983"],
  ["session-token", "123456", "9d75aa38b00f7e027555dc7f8048792e314e53946e5e044c2ca48f71ab45aedf"],
  [
    "session-token",
    "person@example.org",
    "00ad24f1f02dd62c56ba719782b74c339b7ef12a49da1ea7ec847b2d9045b763",
  ],
  [
    "session-token",
    "Grüße 🔑 \u0000 end",
    "38ae19de5b3ad25616668851d63a868f617b6090c4797dedd0721ef9d5f44c32",
  ],
  [
    "session-token",
    "lone \ud800 surrogate",
    "dcc188b1db3785f46a1fa5890ed2c51792e97d909bb552ce6827cb979baa30fd",
  ],
  ["webauthn-challenge", "", "9fe42483147f793dcd6638c690aa3d73382b2f3389c92f796a8446f2f3408dec"],
  [
    "webauthn-challenge",
    "123456",
    "31688099b51d48ca3a69b7eb57f5cfd9eea0f4889950596e8d46c74fba76a3f3",
  ],
  [
    "webauthn-challenge",
    "person@example.org",
    "df00aa451231762216bc45945d089ed4eb7d2a2ee336b39a0dce879203ba1ac9",
  ],
  [
    "webauthn-challenge",
    "Grüße 🔑 \u0000 end",
    "1fdb79026eb7b0e32780e24eb239b74db9f91a87497a8b3a89de4c7c6e8805c5",
  ],
  [
    "webauthn-challenge",
    "lone \ud800 surrogate",
    "4893fe82139188cc96b06d845d8885dc25f7395d574370c70322ebcbc85f0f4d",
  ],
  ["enrollment-token", "", "37e4c05926c315d5ffefa6235c6a4a0ee5718666267072f08b5e2f4af0d6c5fe"],
  [
    "enrollment-token",
    "123456",
    "0dd99f881431c6ba45fcdc5f1f15b9dd3c6d094a47a3d507b452916d507cfd9d",
  ],
  [
    "enrollment-token",
    "person@example.org",
    "aad2b50ba6a0d590c205e0c5e790eb6cf14e694b40eb414ab84fcea87b936de3",
  ],
  [
    "enrollment-token",
    "Grüße 🔑 \u0000 end",
    "b3db71e95f5e1a8434e1795984dda1b39486f96c1e25623a6b07528a4bcd079a",
  ],
  [
    "enrollment-token",
    "lone \ud800 surrogate",
    "a67d5cb1c420011b163acd2689d301cf08b80ec07069282115a9efd4bff7e5c1",
  ],
  ["person-key", "", "6dee605ee2dd41ffee18875854c5350ce87f2dc49fb2dc4b9959a3662d0dd79f"],
  ["person-key", "123456", "0df2f7cd3f2b04f8851e1a1ae38e1a9e0f9bedf854e7ab4ef373835de1b58d4f"],
  [
    "person-key",
    "person@example.org",
    "581bc935d28b2e75f892afab0c735c629b04a5324faa6b68cb5efd06840a8db1",
  ],
  [
    "person-key",
    "Grüße 🔑 \u0000 end",
    "40f2528f447a0c70e6e0baff42c441d5f26827e40e6f5758f696c4eba67b62d0",
  ],
  [
    "person-key",
    "lone \ud800 surrogate",
    "e6ff48b544a2a98efde8e06ef665f8c1e583838114cac03bad4e2293ddb2ee60",
  ],
  ["approval-id", "", "a0a587a278fd5fd363b9974f96e0f8ef6564f4d1aeeca0a6b0241a5e9b5d4534"],
  ["approval-id", "123456", "8d4b8598c00b748c0bd6c939c43a05b83112de5fb4ca21f861775e432428e68c"],
  [
    "approval-id",
    "person@example.org",
    "33d25f468ecf4a9a39874393b64336c47b412d111f1b206a485c1020d85e3f5a",
  ],
  [
    "approval-id",
    "Grüße 🔑 \u0000 end",
    "5f26ade38b9fab97eab2998d94a6601151d76d08cb574ed58555ac429bba2d05",
  ],
  [
    "approval-id",
    "lone \ud800 surrogate",
    "62eb91e1f5eaba17587d8213b635682642c5c3235143237878c534db6b676231",
  ],
  ["approval-evidence", "", "587fa2cbdd94f678a8c5441e9c8bd656041c6d612b2afa8a82f3c44f57353369"],
  [
    "approval-evidence",
    "123456",
    "170a0e5ada86a4ae836ef4f74e9611ff29649b5e29b8d00397629caf8e6e99fb",
  ],
  [
    "approval-evidence",
    "person@example.org",
    "c86595e8a7cb06bc4f67176b6f37372b97a4f367a17c19c669fbb0fb8d2071b0",
  ],
  [
    "approval-evidence",
    "Grüße 🔑 \u0000 end",
    "5e71e540e0c1e5241a024f08d65578408c9265932a4e83cd3893ccb70aa79795",
  ],
  [
    "approval-evidence",
    "lone \ud800 surrogate",
    "64c2f249d340f6110408bd4171b1957aed3c4e257e5acd33de443460252dbad5",
  ],
];

/** [plaintext hex, context, sealed] for createAesGcmSealer({ k1, old }). */
export const SEALED: [string, string, string][] = [
  ["01", "ctx", "v1.k1.ORP7OaQPlp8L8gQ3.TA.9Ljx4_ecpg0gW_ZWPl_mWA"],
  [
    "3132333435363738393031323334353637383930",
    "identkit/totp-secret\u0000factor-1\u0000account-1",
    "v1.k1.bN79e21N9wdhveBS.lrMWOBAOfhO6P1SuxTmoCDILB5A.pITyiN_mwM65zQj3bTdobA",
  ],
  [
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "Grüße \u0000 ctx",
    "v1.k1.QzXCseX03Gqw2FpQ.kazaTWc593Y2wcL5RkNlJqqB70fH1dWPt744hqqjuQEUcYM1jYsU_1UG22-UdTTmtR_uT4OXnvQcy1iV8TETLA.iQk0mjRyXvGzrNRPISb2Zw",
  ],
  [
    "3132333435363738393031323334353637383930",
    "identkit/totp-secret\u0000factor-1\u0000account-1",
    "v1.old.bBMz_pn5dH76IM4h.acCgMA7N0JNF6iQgW8D4lzcJK0Q.fLRNwc7wS5m7e7XPyNiFHg",
  ],
];

/** [payload, hashPayload(payload)]; "bytes:<hex>" means a Uint8Array payload. */
export const PAYLOAD_HASHES: [string, string][] = [
  ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  ["release 1", "c40ffd4b1da7805cbba7f81a2f97c3ef3aa9d1455588357845a94165683a9c23"],
  [
    '{"request":"release","amount":100}',
    "24fcf74ba5eeae4bcea7b8ad1cfa2e86f1b87e673760f44d8ce77326cfdb6e1b",
  ],
  ["bytes:000102ff", "3d1f57c984978ef98a18378c8166c1cb8ede02c03eeb6aee7e2f121dfeee3e56"],
];

/** [nonce, payloadHash, accountId, approvalChallenge(...)]. */
export const APPROVAL_CHALLENGES: [string, string, string, string][] = [
  [
    "nonce-1",
    "c40ffd4b1da7805cbba7f81a2f97c3ef3aa9d1455588357845a94165683a9c23",
    "account-1",
    "_esywGNfViulcWWORfF3ijNSGn0PYRBbxJna0zYwDKo",
  ],
  // A vector that a consumer pins in its documentation.
  [
    "q1w2e3r4t5y6u7i8o9p0aA",
    "4f6066c89d67ce45f43d8b020042199188957dfbdb4e927c516c86a32788c5ce",
    "00000000-0000-4000-8000-0000000000b1",
    "iv-DzjO4su3htLYEbbm5iOKg3VYR60qzLHDhcZvjdYg",
  ],
];
