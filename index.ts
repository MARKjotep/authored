import { randomBytes } from "node:crypto";
import { CryptoHasher, file, gunzipSync, gzipSync, write } from "bun";
import { Client } from "pg";
import { promises as fr, mkdirSync, writeFileSync } from "node:fs";
import { sign, verify } from "jsonwebtoken";

import { O, str, get, is, Time } from "../_misc/__";

export function decodeSID(str: string) {
  const hash = new CryptoHasher("md5");
  hash.update(str);
  return hash.digest("hex");
}
const textD = new TextDecoder();

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
const _is = {
  file: (path: string, data?: string) => {
    try {
      writeFileSync(path, data ?? "", { flag: "wx" });
    } catch (error) {
      //
    }
    return true;
  },
  dir: (path: string) => {
    mkdirSync(path, { recursive: true });
    return true;
  },
  decode(str: any) {
    return textD.decode(str);
  },
};

/*
-------------------------
Utils
-------------------------
*/

interface obj<T> {
  [Key: string]: T;
}
interface fs {
  [key: string]: string | undefined | boolean | number;
}
interface bs {
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}

interface sesh_db {
  sid: string;
  data: string;
  expiration: string;
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}

function hashedToken(len = 64) {
  return new CryptoHasher("sha256").update(randomBytes(len)).digest("hex");
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
      return true;
    }
    return false;
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

export class ServerSide extends callBack {
  [Key: string]: any;
  modified: boolean;
  private readonly readOnly: boolean;
  constructor(
    public sid: string = "",
    initial: obj<string> = {},
    readonly = false,
  ) {
    super(initial);
    this.modified = false;
    this.readOnly = readonly;
  }
  get session() {
    return new Proxy<ServerSide>(this, this);
  }
}

class Signator {
  constructor(public salt: string) {}
  getSignature(val: string) {
    const key = this.deriveKey().toString();
    return str.digest(key, val).toString("base64");
  }
  deriveKey() {
    return str.digest(this.salt);
  }
  sign(val: string) {
    const sig = this.getSignature(val);
    const vals = str.buffer(val + "." + sig);
    return _is.decode(vals);
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
}

class sidGenerator {
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

export class AuthInterface extends sidGenerator {
  constructor(
    public config: authConfig,
    salt?: string,
  ) {
    super(salt ?? "salty");
  }
  async openSession(sid?: string, readonly?: boolean): Promise<ServerSide> {
    if (sid && this.signer.unsign(sid))
      return await this.fetchSession(sid, readonly);
    return this.new;
  }
  async fetchSession(sid: string, readonly?: boolean): Promise<ServerSide> {
    return this.new;
  }
  async saveSession(
    sesh: ServerSide,
    X?: Headers,
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
  get getExpiration(): string | null {
    const now = new Date();
    const lifet = this.config.LIFETIME;
    return now.setDate(now.getDate() + lifet).toString();
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
        const GX = JSON.parse(_is.decode(gunzipSync(data)));
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

    _is.file(fpath, "");
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

  constructor(
    config: authConfig,
    cacherpath = ".sessions",
    public isJWT: boolean = false,
  ) {
    super(config);
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
    X?: Headers,
    deleteMe: boolean = false,
  ): Promise<void> {
    const sCookie = (life: 0 | Date) => {
      if (X) {
        const cookie = this.setCookie(sesh, life);
        if (X) {
          X.set("Set-Cookie", cookie);
        }
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

// Single query --
export class PGCache<T extends bs> {
  client: Client;
  query: string;
  f_timed: number;
  data: Map<any, T>;
  key: string;
  constructor(client: Client, key: string, query: string) {
    this.query = query;
    this.key = key;
    this.f_timed = Date.now();
    this.data = new Map();
    this.client = client;
  }
  async init(val: string): Promise<T | null> {
    const TQ = await this.client.query({
      text: this.query + ` where ${this.key} = $1`,
      values: [val],
    });
    // Delete keys with no value
    for (const [k, v] of this.data) {
      if (!v) {
        this.data.delete(k);
      }
    }
    if (TQ.rowCount) {
      const tr = TQ.rows[0];
      tr.f_timed = Date.now();
      this.data.set(val, tr);
      return tr;
    } else {
      this.data.set(val, null as any);
      return null;
    }
  }
  async checkLast(time: number) {
    const xl = new Date(time);
    xl.setMinutes(xl.getMinutes() + 15);
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
  async set(data: T) {
    if (this.key in data) {
      data.f_timed = Date.now();
      this.data.set(data[this.key], data);
    }
  }
  async delete(key: string) {
    this.data.delete(key);
  }
}

class postgreSession extends ServerSide {}

class PostgreSQL extends AuthInterface {
  sclass: typeof ServerSide = postgreSession;
  client: Client;
  pgc: PGCache<sesh_db>;
  constructor(client: Client, config: authConfig) {
    super(config);
    this.client = client;
    this.pgc = new PGCache<sesh_db>(client, "sid", `SELECT * FROM session`);
  }
  async fetchSession(sid: string) {
    const prefs = this.config.KEY_PREFIX + sid;
    const itms = await this.pgc.get(prefs);
    let data = {};
    if (itms) {
      data = JSON.parse(itms.data);
    }
    return new this.sclass(sid, data).session;
  }
  async saveSession(
    xsesh: ServerSide,
    rsx?: any,
    deleteMe?: boolean,
    sameSite: string = "",
  ): Promise<void> {
    const prefs = this.config.KEY_PREFIX + xsesh.sid;
    if (!Object.entries(xsesh.data).length) {
      if (xsesh.modified || deleteMe) {
        if (rsx) {
          await this.client.query({
            text: `DELETE FROM session WHERE sid = $1`,
            values: [prefs],
          });

          await this.pgc.delete(prefs);
          const cookie = this.setCookie(xsesh, 0);
          rsx.header = { "Set-Cookie": cookie };
        }
      }
      return;
    }

    const life = new Time().timed({ day: this.config.LIFETIME });
    const data = JSON.stringify(xsesh.data);

    if (rsx) {
      const expre = this.getExpiration;
      await this.client.query({
        text: `INSERT INTO session(sid, data, expiration) VALUES($1, $2, $3)`,
        values: [prefs, data, expre ? expre : null],
      });
      await this.pgc.set({
        sid: prefs,
        data: data,
        expiration: expre ?? "",
        life: Time.now,
      });
      const cookie = this.setCookie(xsesh, life);
      rsx.header = { "Set-Cookie": cookie };
    }
  }
}

/*
-------------------------
JWT
-------------------------
*/

// export class JWT extends ServerSide {}

export class JWTInterface extends sidGenerator {
  salt: string;
  constructor() {
    super("salty_jwt");
    this.salt = "salty_jwt";
  }
  sign(payload: obj<any>) {
    const options = {
      issuer: this.salt, // Issuer of the token
    };
    const datax = {
      data: payload,
    };

    return sign(datax, get.secret(), options);
  }
  get random() {
    const options = {
      issuer: this.salt, // Issuer of the token
    };
    const datax = {
      data: hashedToken(),
    };
    return sign(datax, get.secret(), options);
  }
  jwt() {
    //
    const rid = this.generate();
    return new ServerSide(rid).session;
  }
  verify(
    payload: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ): obj<string> | null {
    try {
      const ever = verify(payload, get.secret());

      if (ever) {
        const { data, iat, iss } = ever as any;
        if (iss == this.salt) {
          if (time) {
            const { days, hours, minutes, seconds } = time;
            let endD = new Date(iat * 1000);
            if (days) {
              endD = new Date(endD.setDate(endD.getDate() + days));
            } else if (hours) {
              endD = new Date(endD.setHours(endD.getHours() + hours));
            } else if (minutes) {
              endD = new Date(endD.setMinutes(endD.getMinutes() + minutes));
            } else if (seconds) {
              endD = new Date(endD.setSeconds(endD.getSeconds() + seconds));
            }
            if (endD.getTime() - Date.now() > 0) {
              return data as obj<string>;
            }
          } else {
            return data as obj<string>;
          }
        }
      }
    } catch (e) {}

    return null;
  }
  open(
    token: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ): ServerSide {
    if (token) {
      const tv = this.verify(token, time);
      if (tv) {
        return new ServerSide(token, tv, true).session;
      }
    }

    return this.jwt();
  }
  save(xjwts: ServerSide) {
    const data = xjwts.data;
    if ("access_token" in data) {
      delete data["access_token"];
    }
    return this.sign(data);
  }
  new(payload: obj<any>) {
    return this.sign(payload);
  }
}

// json files CACHED reader --
export class Fjson<T extends fs> {
  fs: string;
  f_timed: number;
  data: Map<any, T>;
  key: string;
  dir: string;
  constructor({ dir, fs, key }: { dir: string; fs: string; key: string }) {
    this.dir = dir + "/ffs";
    this.key = key;
    this.f_timed = Date.now();
    this.data = new Map();
    this.fs = this.dir + `/${fs}.json`;
  }
  async init() {
    if (_is.dir(this.dir) && _is.file(this.fs, "{}")) {
      file(this.fs)
        .text()
        .then((e) => {
          const FJSON = JSON.parse(e);
          this.data = new Map(O.items(FJSON));
        })
        .catch((e) => {
          e;
        });
    }
  }
  async get(val: string | undefined): Promise<T | null> {
    const hdat = this.data.get(val);
    if (hdat) return hdat;
    return null;
  }
  async set(data: T) {
    if (this.key in data) {
      const frr = await file(this.fs).text();
      if (frr) {
        const FJSON = JSON.parse(frr);
        const dtk = data[this.key] as string;
        FJSON[dtk] = data;
        await write(this.fs, JSON.stringify(FJSON));
      }
      this.data.set(data[this.key], data);
    }
  }
  async delete(key: string) {
    if (await this.get(key)) {
      const frr = await file(this.fs).text();
      if (frr) {
        const FJSON = JSON.parse(frr.toString());
        if (key in FJSON) {
          delete FJSON[key];
          await write(this.fs, JSON.stringify(FJSON));
        }
        this.data.delete(key);
      }
    }
  }
  async json() {
    const fraw = await file(this.fs).text();
    const JPR = JSON.parse(fraw);
    return O.vals(JPR);
  }
}

/*
-------------------------

-------------------------
*/
