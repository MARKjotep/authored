import { Client } from "pg";
import { authConfig, AuthInterface, dbs } from "./auth";
import { FSInterface } from "./sessions";
export * from "./sessions";
export * from "./auth";
export declare class Auth {
    postgresClient?: Client;
    config: authConfig;
    constructor({ type, dir }?: {
        type?: dbs;
        dir?: string;
    });
    initStorage(path: string): this;
    get session(): AuthInterface;
    get jwt(): FSInterface;
}
