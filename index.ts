/// <reference path="./types/types.d.ts" />
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { CryptoHasher } from "bun";
import { Client } from "pg";

/*
-------------------------
Utils
-------------------------
*/

export const $$ = {
  set p(a: any) {
    if (Array.isArray(a)) {
      console.log(...a);
    } else {
      console.log(a);
    }
  },
  textD: new TextDecoder(),
};

export const O = {
  vals: Object.values,
  keys: Object.keys,
  items: Object.entries,
  has: Object.hasOwn,
  define: Object.defineProperty,
  ass: Object.assign,
  length: (ob: Object) => {
    return Object.keys(ob).length;
  },
};

/*
-------------------------
AUTHORED
-------------------------
*/

type authConfig = {
  COOKIE_NAME: string;
  COOKIE_DOMAIN: string;
  COOKIE_PATH: string;
  COOKIE_HTTPONLY: boolean;
  COOKIE_SECURE: boolean;
  REFRESH_EACH_REQUEST: boolean;
  COOKIE_SAMESITE: string;
  KEY_PREFIX: string;
  PERMANENT: boolean;
  USE_SIGNER: boolean;
  ID_LENGTH: number;
  FILE_THRESHOLD: number;
  LIFETIME: number;
  MAX_COOKIE_SIZE: number;
  INTERFACE: dbs;
  STORAGE: string;
  JWT_STORAGE: string;
  JWT_LIFETIME: number;
};

type dbs = "fs" | "postgres";
export class Auth {
  postgresClient?: Client;
  config: authConfig = {
    COOKIE_NAME: "session",
    COOKIE_DOMAIN: "127.0.0.1",
    COOKIE_PATH: "/",
    COOKIE_HTTPONLY: true,
    COOKIE_SECURE: true,
    REFRESH_EACH_REQUEST: false,
    COOKIE_SAMESITE: "Strict",
    KEY_PREFIX: "session:",
    PERMANENT: true,
    USE_SIGNER: false,
    ID_LENGTH: 32,
    FILE_THRESHOLD: 500,
    LIFETIME: 31,
    MAX_COOKIE_SIZE: 4093,
    INTERFACE: "fs",
    STORAGE: ".sessions",
    JWT_STORAGE: ".jwt",
    JWT_LIFETIME: 5,
  };
  constructor(type: dbs) {
    this.config.INTERFACE = type;
  }
  initStorage(path: string = "./") {
    this.config.STORAGE = path + this.config.STORAGE;
    this.config.JWT_STORAGE = path + this.config.JWT_STORAGE;
  }
}

/*
-------------------------
Session manager for both cookie and JWT
-------------------------
*/

class callBack {
  [Key: string]: any;
  data: obj<string>;
  modified: boolean;
  new: boolean = true;
  length = 0;
  constructor(initial: obj<string> = {}) {
    this.modified = true;
    this.data = {};
    this.length = O.length(initial);
    if (this.length) {
      this.new = false;
    }
    O.ass(this.data, initial);
  }
  set(target: any, prop: string, val: string) {
    if (!this.readonly && target.data[prop] != val) {
      this.modified = true;
      target.data[prop] = val;
      if (!(prop in target.data)) {
        this.length++;
      }
    }
    return target;
  }
  get(target: any, prop: string) {
    if (prop in target) {
      return target[prop];
    }
    return target.data[prop];
  }
  has(target: any, prop: string) {
    if (prop in target.data) {
      return true;
    }
    return false;
  }
  deleteProperty(target: any, val: string) {
    if (!this.readonly && val in target.data) {
      this.modified = true;
      delete target.data[val];
    }
    return true;
  }
}

class ServerSide extends callBack {
  [Key: string]: any;
  modified: boolean;
  sid: string;
  private readonly readonly: boolean;
  constructor(sid: string = "", initial: obj<string> = {}, readonly = false) {
    super(initial);
    this.modified = false;
    this.sid = sid;
    this.readonly = readonly;
    // this.permanent = permanent;
  }
  get session() {
    return new Proxy<ServerSide>(this, this);
  }
}

function hmacDigest(salt: string) {
  const hmac = new Bun.CryptoHasher("sha256", salt);
  // hmac.update(update);
  return hmac.digest();
}
function str2Buffer(str: string): Buffer {
  return Buffer.from(str);
}
function decode(str: any) {
  return $$.textD.decode(str);
}

class Signator {
  salt: string;
  constructor(salt: string) {
    this.salt = salt;
  }
  getSignature(val: string) {
    const vals = str2Buffer(val);
    return hmacDigest(this.salt).toString("base64");
  }
  deriveKey() {
    return hmacDigest(this.salt);
  }
  sign(val: string) {
    const sig = this.getSignature(val);
    const vals = str2Buffer(val + "." + sig);
    return decode(vals);
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
      const sval = str2Buffer(vals);
      const sept = str2Buffer(".").toString()[0];
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
  generate(len = 21) {
    const rbyte = randomBytes(len);
    let lbyte = rbyte.toString("base64");
    if (lbyte.endsWith("=")) {
      lbyte = lbyte.slice(0, -1);
    }
    return this.sign(lbyte);
  }
}

class AuthInterface extends Signator {
  constructor(salt?: string) {
    super(salt ?? "salty");
  }
  async openSession(sid: string): Promise<ServerSide> {
    if (this.unsign(sid)) return await this.fetchSession(sid);
    return this.new;
  }
  async fetchSession(sid: string): Promise<ServerSide> {
    return this.new;
  }
  async saveSession(): Promise<void> {
    return;
  }
  get new() {
    return new ServerSide(this.generate(), {}).session;
  }
  get readonly() {
    return new ServerSide(this.generate(), {}, true).session;
  }
}

/*
-------------------------

-------------------------
*/

//
const sk = "helloworld";
const CH = new CryptoHasher("sha256");

function dSecret() {
  return CH.copy().update(sk).digest(); // Hash to 32 bytes
}
function encrypt(text: string) {
  const secretKey = dSecret() as any;
  const iv = randomBytes(16) as any; // Initialization vector
  const cipher = createCipheriv("aes-256-cbc", secretKey, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return `${iv.toString("hex")}:${encrypted}`; // Return IV and encrypted data
}
function decrypt(encryptedData: string) {
  const secretKey = dSecret() as any;
  const [ivHex, encryptedText] = encryptedData.split(":");
  const iv = Buffer.from(ivHex, "hex") as any;
  const decipher = createDecipheriv("aes-256-cbc", secretKey, iv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
