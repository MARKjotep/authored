import { Client } from "pg";
import { authConfig, AuthInterface, dbs } from "./auth";
import { FSInterface, PGInterface } from "./sessions";

export * from "./sessions";
export * from "./auth";

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
