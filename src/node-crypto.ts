import { IdentkitError } from "./errors.js";

/**
 * The part of `node:crypto` that the sync, Node-only exports use. Declared here, so neither
 * the code nor the published types import `node:crypto`.
 */
interface NodeHash {
  update(data: string | Uint8Array, encoding?: "utf8"): NodeHash;
  digest(): Uint8Array;
  digest(encoding: "hex" | "base64url"): string;
}

export interface NodeKeyObject {
  export(options: { format: "jwk" }): { x?: string; y?: string };
}

export interface NodeCrypto {
  createHash(algorithm: string): NodeHash;
  createHmac(algorithm: string, key: string | Uint8Array): NodeHash;
  generateKeyPairSync(
    type: "ec",
    options: { namedCurve: "P-256" },
  ): { privateKey: NodeKeyObject; publicKey: NodeKeyObject };
  sign(algorithm: string, data: Uint8Array, key: NodeKeyObject): Uint8Array;
}

/** A sync, Node-only export was called in a runtime without `node:crypto`. */
export class NodeCryptoUnavailableError extends IdentkitError {
  constructor(name: string, alternative: string) {
    super(
      "node_crypto_unavailable",
      `${name} needs node:crypto, which this runtime does not provide; use ${alternative}`,
    );
  }
}

/**
 * Loads `node:crypto` without a static import, so modules that use it still load in runtimes
 * without Node modules. Throws `NodeCryptoUnavailableError` that names `alternative` there.
 */
export function nodeCrypto(name: string, alternative: string): NodeCrypto {
  // `process` is missing in runtimes without Node globals, `getBuiltinModule` before Node 22.3.
  // The private key type of the interface is narrower than Node's key union, so Node's module
  // does not type-check as NodeCrypto. It is Node's own module: the members exist as declared.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  const loaded = globalThis.process?.getBuiltinModule?.("node:crypto") as NodeCrypto | undefined;
  if (!loaded) throw new NodeCryptoUnavailableError(name, alternative);
  return loaded;
}
