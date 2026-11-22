import { createMemoryStore } from "../src/index.js";
import { runStoreContract } from "./store-contract.js";

runStoreContract("memory", () => createMemoryStore());
