import { randomBytes } from "node:crypto";
import { Signator } from "../signer";
import { CryptoHasher } from "bun";

export class sidGenerator {
  signer: Signator;
  constructor(salt: string) {
    this.signer = new Signator(salt);
  }
  generate(len = 21) {
    const rbyte = randomBytes(len);
    let lbyte = rbyte.toString("base64");
    if (lbyte.endsWith("=")) {
      lbyte = lbyte.slice(0, -1);
    }
    return this.signer.sign(lbyte);
  }
}

export function decodeSID(str: string) {
  const hash = new CryptoHasher("md5");
  hash.update(str);
  return hash.digest("hex");
}
