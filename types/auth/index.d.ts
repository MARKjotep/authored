import { Client } from "pg";
import { AuthInterface } from "./interface";
import { authConfig, dbs } from "./config";
import { FSInterface } from "../session";
export * from "./server";
export { AuthInterface, authConfig };
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
