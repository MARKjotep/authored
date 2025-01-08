import { authConfig } from "./config";
import { ServerSide } from "./server";
import { sidGenerator } from "../sid";
export declare class AuthInterface extends sidGenerator {
    config: authConfig;
    constructor(config: authConfig, salt?: string);
    openSession(sid?: string, readonly?: boolean): Promise<ServerSide>;
    fetchSession(sid: string, readonly?: boolean): Promise<ServerSide>;
    saveSession(sesh: ServerSide, X?: Headers, deleteMe?: boolean): Promise<void>;
    get new(): ServerSide;
    get readonly(): ServerSide;
    get getExpiration(): string | null;
    setCookie(xsesh: ServerSide, life: Date | number, _sameSite?: string): string;
    loadHeader(req: any, readonly?: boolean): Promise<ServerSide>;
}
