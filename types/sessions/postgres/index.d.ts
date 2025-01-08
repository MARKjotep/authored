import { Client } from "pg";
import { authConfig, AuthInterface } from "../../auth";
import { ServerSide } from "../../auth";
import { PGCache } from "./cache";
export { PGCache };
export declare class PostgreSession extends ServerSide {
}
interface sesh_db {
    sid: string;
    data: string;
    expiration: string;
    f_timed?: number;
    [key: string]: string | undefined | boolean | number;
}
export declare class PGInterface extends AuthInterface {
    sclass: typeof ServerSide;
    client: Client;
    pgc: PGCache<sesh_db>;
    constructor(client: Client, config: authConfig);
    fetchSession(sid: string): Promise<ServerSide>;
    saveSession(xsesh: ServerSide, rsx?: any, deleteMe?: boolean, sameSite?: string): Promise<void>;
}
