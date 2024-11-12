/// <reference path="./types/types.d.ts" />
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { CryptoHasher, file, gunzipSync, gzipSync, write, serve } from "bun";
import { Client } from "pg";
import { mkdirSync, statSync, writeFileSync, promises as fr } from "node:fs";

/*
-------------------------
Utils
-------------------------
*/

const $$ = {
  set p(a: any) {
    if (Array.isArray(a)) {
      console.log(...a);
    } else {
      console.log(a);
    }
  },
  textD: new TextDecoder(),
};

const O = {
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

const str = {
  rbytes: new RegExp(/(\d+)(\d*)/, "m"),
  strip: (char: string, tostrip: string) => {
    let _char = char;
    if (_char.startsWith(tostrip)) {
      _char = _char.slice(1);
    }
    if (_char.endsWith(tostrip)) {
      _char = _char.slice(0, -1);
    }
    return _char;
  },
  decode(str: any) {
    return $$.textD.decode(str);
  },
  buffer(str: string): Buffer {
    return Buffer.from(str);
  },
  digest(salt: string) {
    const hmac = new Bun.CryptoHasher("sha256", salt);
    hmac.update("hello");
    return hmac.digest();
  },
};

const is = {
  bool: (v: any) => typeof v === "boolean",
  str: (v: any) => typeof v === "string",
  arr: (v: any) => Array.isArray(v),
  file: async (path: string, data?: string) => {
    try {
      return statSync(path).isFile();
    } catch (err) {
      if (data !== undefined) writeFileSync(path, Buffer.from(data));
      return true;
    }
  },
  dir: (path: string) => {
    try {
      return statSync(path).isDirectory();
    } catch (err) {
      mkdirSync(path, { recursive: true });
      return true;
    }
  },
  number: (value: any) => {
    return !isNaN(parseFloat(value)) && isFinite(value);
  },
  dict: (val: object) => {
    return typeof val === "object" && val !== null && !Array.isArray(val);
  },
  arraybuff: (val: any) => {
    return (
      val instanceof Uint8Array ||
      val instanceof ArrayBuffer ||
      typeof val === "string"
    );
  },
};

const html = {
  cookie: (
    key: string,
    value: string = "",
    {
      maxAge,
      expires,
      path,
      domain,
      secure,
      httpOnly,
      sameSite,
    }: {
      maxAge?: Date | number;
      expires?: Date | string | number;
      path?: string | null;
      domain?: string;
      secure?: boolean;
      httpOnly?: boolean;
      sameSite?: string | null;
      sync_expires?: boolean;
      max_size?: number;
    },
  ) => {
    if (maxAge instanceof Date) {
      maxAge = maxAge.getSeconds();
    }

    if (expires instanceof Date) {
      expires = expires.toUTCString();
    } else if (expires === 0) {
      expires = new Date().toUTCString();
    }

    const cprops = [
      ["Domain", domain],
      ["Expires", expires],
      ["Max-Age", maxAge],
      ["Secure", secure],
      ["HttpOnly", httpOnly],
      ["Path", path],
      ["SameSite", sameSite],
    ];

    return cprops
      .reduce<string[]>(
        (acc, [kk, v]) => {
          if (v !== undefined) acc.push(`${kk}=${v}`);
          return acc;
        },
        [`${key}=${value}`],
      )
      .join("; ");
  },
};

class Time {
  date: Date;
  constructor(dateMS?: number) {
    this.date = dateMS ? new Date(dateMS) : new Date();
  }
  delta(date2: number | null = null, _Date: boolean = false) {
    const TD = Time.delta(this.date.getTime(), date2);
    return _Date ? new Date(TD) : TD;
  }
  //
  timed(time?: {
    year?: number;
    month?: number;
    day?: number;
    hour?: number;
    minute?: number;
    second?: number;
  }) {
    const tmd = this.date.getTime();
    let endD = this.date;
    if (time) {
      const { year, month, day, hour, minute, second } = time;
      if (year) {
        endD = new Date(endD.setFullYear(endD.getFullYear() + year));
      }
      if (month) {
        endD = new Date(endD.setMonth(endD.getMonth() + month));
      }
      if (day) {
        endD = new Date(endD.setDate(endD.getDate() + day));
      }
      if (hour) {
        endD = new Date(endD.setHours(endD.getHours() + hour));
      }
      if (minute) {
        endD = new Date(endD.setMinutes(endD.getMinutes() + minute));
      }
      if (second) {
        endD = new Date(endD.setSeconds(endD.getSeconds() + second));
      }
    }
    return endD;
  }
  static delta(date1: number, date2: number | null = null) {
    if (date2) {
      return date2 - date1;
    } else {
      return date1 - Date.now();
    }
  }
  static get now() {
    return Date.now();
  }
}

function decodeSID(name: string) {
  const bkey = str.buffer(name);
  const hash = new CryptoHasher("md5");
  hash.update(bkey);
  return hash.digest("hex");
}

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
  constructor({ type = "fs", dir }: { type?: dbs; dir?: string } = {}) {
    type && (this.config.INTERFACE = type);
    dir && this.initStorage(dir);
  }
  initStorage(path: string) {
    this.config.STORAGE = path + "/" + this.config.STORAGE;
    this.config.JWT_STORAGE = path + "/" + this.config.JWT_STORAGE;
    return this;
  }
  get session(): AuthInterface {
    return new FSInterface(this.config, this.config.STORAGE);
  }
  get jwt() {
    return new FSInterface(this.config, this.config.JWT_STORAGE);
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
      if (!(prop in target.data)) {
        this.length++;
      }
      target.data[prop] = val;
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
      this.length--;
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

class Signator {
  salt: string;
  constructor(salt: string) {
    this.salt = salt;
  }
  getSignature(val: string) {
    const vals = str.buffer(val);
    return str.digest(this.salt).toString("base64");
  }
  deriveKey() {
    return str.digest(this.salt);
  }
  sign(val: string) {
    const sig = this.getSignature(val);
    const vals = str.buffer(val + "." + sig);
    return str.decode(vals);
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
      const sval = str.buffer(vals);
      const sept = str.buffer(".").toString()[0];
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
  config: authConfig;
  constructor(config: authConfig, salt?: string) {
    super(salt ?? "salty");
    this.config = config;
  }
  async openSession(sid?: string, readonly?: boolean): Promise<ServerSide> {
    if (sid && this.unsign(sid)) return await this.fetchSession(sid, readonly);
    return this.new;
  }
  async fetchSession(sid: string, readonly?: boolean): Promise<ServerSide> {
    return this.new;
  }
  async saveSession(
    sesh: ServerSide,
    headers?: obj<string>,
    deleteMe: boolean = false,
  ): Promise<void> {
    return;
  }
  get new() {
    return new ServerSide(this.generate(), {}).session;
  }
  get readonly() {
    return new ServerSide(this.generate(), {}, true).session;
  }
  setCookie(xsesh: ServerSide, life: Date | number, _sameSite = "") {
    let sameSite = null;
    let xpire: obj<any> = {};
    if (this.config.COOKIE_SAMESITE) {
      sameSite = this.config.COOKIE_SAMESITE;
    }

    if (_sameSite) {
      sameSite = _sameSite;
    }
    if (life === 0) {
      xpire.maxAge = life.toString();
    } else {
      xpire.expires = life;
    }

    return html.cookie(this.config.COOKIE_NAME!, xsesh.sid, {
      domain: "",
      path: this.config.COOKIE_PATH,
      httpOnly: this.config.COOKIE_HTTPONLY,
      secure: this.config.COOKIE_SECURE,
      sameSite: sameSite,
      ...xpire,
    });
  }
  async loadHeader(req: any, readonly?: boolean) {
    const CK = async (ck?: string) => {
      let sid: string | undefined = "";
      if (ck) {
        let cc = ck.split(";").reduce<obj<string>>((ob, d) => {
          const [key, val] = d.trim().split(/=(.*)/s);
          ob[key] = val;
          return ob;
        }, {});
        sid = cc.session;
      }

      const prefs = sid;
      return await this.openSession(prefs, readonly);
    };
    let RH = req.headers;
    if (RH) {
      if ("get" in RH) {
        return await CK(RH.get("cookie"));
      } else if ("cookie" in RH) {
        return await CK(RH.cookie);
      }
    }

    return this.new;
  }
}

/*
-------------------------
FS = file system cached
-------------------------
*/
export class FSession extends ServerSide {}

// Cache the folder contents in JSON
interface ffcache {
  [key: string]: string | undefined | boolean | number;
  f_timed?: number;
  data: string;
  life: number;
}
class FSCached<T extends bs> {
  path: string;
  data: Map<any, T>;
  constructor(folderpath: string) {
    this.data = new Map();
    this.path = folderpath + "/";
  }
  async init(val: string): Promise<T | null> {
    const fname = decodeSID(val);
    const fpath = this.path + fname;

    const FL = file(fpath);

    if (await FL.exists()) {
      const data = await FL.arrayBuffer();
      try {
        const GX = JSON.parse(str.decode(gunzipSync(data)));
        GX.f_timed = Date.now();
        this.data.set(fname, GX);
        return GX;
      } catch (error) {}
    }
    return null;
  }
  async checkLast(time: number) {
    const xl = new Date(time);
    xl.setMinutes(xl.getMinutes() + 60);
    if (xl.getTime() < Date.now()) {
      return true;
    }
    return false;
  }
  async get(val: string | undefined): Promise<T | null> {
    if (val) {
      const hdat = this.data.get(val);
      if (hdat == undefined) {
        return await this.init(val);
      } else {
        if (hdat && "f_timed" in hdat) {
          const atv = await this.checkLast(hdat.f_timed!);
          if (atv) {
            return await this.init(val);
          }
        }
        return hdat;
      }
    }
    return null;
  }
  async set(val: string, data: T) {
    const fname = decodeSID(val);
    const fpath = this.path + fname;

    await is.file(fpath, "");
    await write(fpath, gzipSync(JSON.stringify(data)));
    data.f_timed = Date.now();
    this.data.set(val, data);
  }
  async delete(key: string) {
    const fname = decodeSID(key);
    this.data.delete(fname);
    const fpath = this.path + fname;
    file(fpath)
      .exists()
      .then(async (e) => {
        await fr.unlink(fpath);
      })
      .catch();
  }
}
class FSInterface extends AuthInterface {
  cacher: FSCached<ffcache>;
  side = FSession;
  isJWT: boolean;
  constructor(
    config: authConfig,
    cacherpath = ".sessions",
    isJWT: boolean = false,
  ) {
    super(config);
    this.isJWT = isJWT;
    this.cacher = new FSCached(cacherpath);
  }
  life(key: string, lstr: number) {
    const { LIFETIME, JWT_LIFETIME } = this.config;
    const NT = new Time(lstr).timed({
      day: this.isJWT ? JWT_LIFETIME : LIFETIME,
    });
    if (NT.getTime() - new Date().getTime() > 0) {
      return true;
    } else {
      this.cacher.delete(key);
      return false;
    }
  }
  async fetchSession(sid: string, readonly?: boolean): Promise<ServerSide> {
    const prefs = this.config.KEY_PREFIX + sid;
    const dt = await this.cacher.get(prefs);
    let _data = {};
    if (dt) {
      let isL = true;
      if ("life" in dt) {
        isL = this.life(prefs, dt.life);
      }
      _data = isL ? JSON.parse(dt.data) : {};
    }
    return new this.side(sid, _data, readonly).session;
  }
  async saveSession(
    sesh: ServerSide,
    headers?: obj<string>,
    deleteMe: boolean = false,
  ): Promise<void> {
    const sCookie = (life: 0 | Date) => {
      if (headers) {
        const cookie = this.setCookie(sesh, life);
        O.ass(headers, {
          "Set-Cookie": cookie,
        });
      }
    };
    const prefs = this.config.KEY_PREFIX + sesh.sid;

    if (!sesh.length) {
      if (!sesh.new && (sesh.modified || deleteMe)) {
        this.cacher.delete(prefs);
        sCookie(0);
      }
      return;
    }

    if (sesh.new && sesh.modified) {
      const life = new Time().timed({ day: this.config.LIFETIME });
      const data = JSON.stringify(sesh.data);
      await this.cacher.set(prefs, {
        data,
        life: Time.now,
      });
      sCookie(life);
    }

    return;
  }
}

/*
-------------------------
Postgres
-------------------------
*/
class postgreSession extends ServerSide {}

/*
-------------------------

-------------------------
*/

const NA = new Auth({
  dir: __dirname,
});

const SS = NA.session;

serve({
  port: 3000,
  async fetch(request, server) {
    const headers = {
      "Content-Type": "text/html",
    };
    const SL = await SS.loadHeader(request);

    await SS.saveSession(SL, headers);

    //
    return new Response("hello", { headers });
  },
});
