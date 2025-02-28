import { Client } from "pg";
import { AuthInterface } from "./auth/interface";
import { FSInterface, FSCached, FSession } from "./sessions/fileSystem";
import { PGCache, PGInterface, PostgreSession } from "./sessions/postgres";
import { $$, Singleton } from "./@";
import { JWTSession } from "./sessions/jwt";

type dbs = "fs" | "postgres";

export interface authConfig {
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
}

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
    if (this.config.INTERFACE === "postgres" && this.postgresClient) {
      return new PGInterface(this.postgresClient, this.config);
    }

    return new FSInterface(this.config, this.config.STORAGE);
  }
  get jwt() {
    return new FSInterface(this.config, this.config.JWT_STORAGE);
  }
}

export class Session {
  declare session: AuthInterface;
  declare jwt: AuthInterface;
  declare jwtInt: JWTSession;

  init(sh: Auth) {
    this.jwtInt = new JWTSession();
    this.session = sh.session;
    this.jwt = sh.jwt;
  }
}

export { ServerSide } from "./auth/server";
export { AuthInterface };
export { FSInterface, FSCached, FSession };
export { PGCache, PGInterface, PostgreSession };
