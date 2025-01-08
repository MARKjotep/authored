import { AuthInterface } from "./interface";
import { authConfig, dbs } from "./config";
import { buffed, hdigest, strDecode } from "../@";
import { randomBytes } from "node:crypto";
import { CryptoHasher } from "bun";

export { ServerSide } from "./server";
export { AuthInterface, authConfig, dbs };

export class Signator {
  constructor(public salt: string) {}
  getSignature(val: string) {
    const key = this.deriveKey().toString();
    return hdigest(key, val).toString("base64");
  }
  deriveKey() {
    return hdigest(this.salt);
  }
  sign(val: string) {
    const sig = this.getSignature(val);
    const vals = buffed(val + "." + sig);
    return strDecode(vals);
  }
  unsign(signedVal: string) {
    if (!(signedVal.indexOf(".") > -1)) {
      throw Error("No sep found");
    }
    const isept = signedVal.indexOf(".");
    const val = signedVal.slice(0, isept);
    const sig = signedVal.slice(isept + 1);
    return this.verifySignature(val, sig);
  }
  loadUnsign(vals: string) {
    if (this.unsign(vals)) {
      const sval = buffed(vals);
      const sept = buffed(".").toString()[0];
      if (!(sept in sval)) {
        throw Error("No sep found");
      }
      const isept = sval.indexOf(sept);
      const val = sval.subarray(0, isept);

      return Buffer.from(val.toString(), "base64").toString("utf-8");
    }
  }
  verifySignature(val: string, sig: string) {
    return this.getSignature(val) == sig ? true : false;
  }
}

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
