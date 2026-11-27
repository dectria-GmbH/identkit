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

/**
 * [purpose, value, digest] for createHmacHasher(HASH_KEY), for the purposes added after 0.1.1:
 * personal API tokens and the OAuth server. Computed with node:crypto HMAC-SHA-256 over
 * `${purpose}\u0000${value}` (the 0.1.1 rule, checked against DIGESTS above), not with identkit.
 * Fixed from the release that adds them on; do not regenerate.
 */
export const LATER_DIGESTS: [string, string, string][] = [
  ["api-token", "", "9c333fd3988877ce77c45a6850ef719c05b7825fe3cc542a10d0b3e79d7bab79"],
  ["api-token", "123456", "81a4c3e5b31b683759b566175719e9c41911c155d63ff9fe509e099dd0b18855"],
  [
    "api-token",
    "person@example.org",
    "c6441c02622933982fa7c622f45bf3321eadaed9603dfdb8a6e1058ca99537e0",
  ],
  [
    "api-token",
    "Grüße 🔑 \u0000 end",
    "a9d2469edd308ed349604a15e2bb3ad32de18f8ec6952c0e1e03a3ebfa7f2716",
  ],
  [
    "api-token",
    "lone \ud800 surrogate",
    "58354516a4ef856a60f51a05282be451b89d0bd55f4cfc0228828def390935ca",
  ],
  ["oauth-client-secret", "", "368f1e46bf8c8bcb9f3f832cbea9e113403ac8d14bf29cf0507ec75eb7be6546"],
  [
    "oauth-client-secret",
    "123456",
    "eadb691c50631a2c1b051ec567a81075e0078239622f15c73e2630c1778ae59d",
  ],
  [
    "oauth-client-secret",
    "person@example.org",
    "b41d62829952251d3b9bfd7eb9c4aa0a38203c207e62a2d5205e2f632353b63c",
  ],
  [
    "oauth-client-secret",
    "Grüße 🔑 \u0000 end",
    "321330d403144cc84c5c47cd1c3af7faa597738278eb7397b57b4d40d703ff55",
  ],
  [
    "oauth-client-secret",
    "lone \ud800 surrogate",
    "6b95ceac0ee0e0c7b6d15bad5d560d1e3e648e0cf27e2373d487fda49f3a0acf",
  ],
  ["oauth-code", "", "04f753cabbe492097e106c0e5bbc0a0019090d9333218344f0a5df9576c44a18"],
  ["oauth-code", "123456", "ea9d80a40db0269dd91e5c3c6f97a68e35db2b2e66153dd4446b937c4bf96e60"],
  [
    "oauth-code",
    "person@example.org",
    "7788c4e9c80f92e11c7a4ff4229a87c7882730898473f75585eb4dad6251a66b",
  ],
  [
    "oauth-code",
    "Grüße 🔑 \u0000 end",
    "1771775c1e613c69c72daa1b25adaf530d8cbe87308f0dd90f7efb0f7b1a89ef",
  ],
  [
    "oauth-code",
    "lone \ud800 surrogate",
    "138e04fd71e24ef84f1bb0dcb6314b278ac01f355ed80e8a87f5a45e5bef3a81",
  ],
  ["oauth-access-token", "", "a52a465edf1796d32a079ebcf2000b3f556b416dca1e6821cd595fdc43e255c6"],
  [
    "oauth-access-token",
    "123456",
    "6f7b52a4b906d38ca4a5842ee17c79139b278eb7decca7f54ee18d00c627125d",
  ],
  [
    "oauth-access-token",
    "person@example.org",
    "7d7d01ebbf3a091bc644d9295c8a2091a7f581e90c3cb2ad6799e03af0b7805b",
  ],
  [
    "oauth-access-token",
    "Grüße 🔑 \u0000 end",
    "5b8477b6d0bfcbc51cf47cfd1c23ae2edeb6c1bd3f59f442f4465a34df298730",
  ],
  [
    "oauth-access-token",
    "lone \ud800 surrogate",
    "26b891cfa2e57ff980ddbcbb499784c9f2f2fd3baad131adbf709fcd77175a47",
  ],
  ["oauth-refresh-ref", "", "00a04021ade002a13b9be29d144ce4cc2ec8edaa96cb93ea65f58a171eadb016"],
  [
    "oauth-refresh-ref",
    "123456",
    "b4b39229249f8e0a1471c9bc8cc68076e3d9c4947e9c046ca96b96dabca57573",
  ],
  [
    "oauth-refresh-ref",
    "person@example.org",
    "40edc9e546dd4b8a835a34cb8ed17758ff7b0469791c05fa633b3673df7ce763",
  ],
  [
    "oauth-refresh-ref",
    "Grüße 🔑 \u0000 end",
    "c5151d7f12a2d7ee708db880d94750adb0609fee50e44379e22e1fa1e84c402f",
  ],
  [
    "oauth-refresh-ref",
    "lone \ud800 surrogate",
    "b51e93cf3311458f2354f02a278ffbbc13e5b84639282de9d3a6b6fc899821e9",
  ],
  ["oauth-refresh-token", "", "cea36010e9c7864bdd242fcc17ac56b1f16b67c55ccab3df365f09ad89262559"],
  [
    "oauth-refresh-token",
    "123456",
    "c75bb121e3f36e5268d863415f5098c20c425009acaaaa31fce92d1a3254a552",
  ],
  [
    "oauth-refresh-token",
    "person@example.org",
    "1aa078d7d459daeae07953d909a2c4d609c7584a7114e5a82f2a3b7ce9260aa8",
  ],
  [
    "oauth-refresh-token",
    "Grüße 🔑 \u0000 end",
    "ae3056799475181f7ceba556dcba270aecab6f1bc7954cbbb7e272e86f9cdcec",
  ],
  [
    "oauth-refresh-token",
    "lone \ud800 surrogate",
    "82d73a69456822321f753d90e3cabf2c9e13f26e5e6e030e28578dc4539fddce",
  ],
  [
    "oauth-registration-address",
    "",
    "5b0a1937c5a2da6ac7215277230428ad557135808b91d96a3aae898ce05a7403",
  ],
  [
    "oauth-registration-address",
    "123456",
    "9c7901955f29a06b4b8a03a7b32ad43eee50180b3d2fabeab6014a9bb46103f5",
  ],
  [
    "oauth-registration-address",
    "person@example.org",
    "996351e1a249c384850ca51df17cc035138ba62e74d2fc583879fabd3d8bf30f",
  ],
  [
    "oauth-registration-address",
    "Grüße 🔑 \u0000 end",
    "36a18618a185874ac9b94eafce6405db1e47199ece14cb5c1c3446b5f706f245",
  ],
  [
    "oauth-registration-address",
    "lone \ud800 surrogate",
    "055cdab2c8dbccab4b08f2566dfc3836c661c937c33a3a19d06f6d0200f35fa9",
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
