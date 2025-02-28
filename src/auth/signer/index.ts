import { buffed, hdigest, strDecode } from "../../@";

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
