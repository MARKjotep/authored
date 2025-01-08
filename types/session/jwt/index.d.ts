import { obj } from "../../@";
import { sidGenerator } from "../../sid";
import { ServerSide } from "../../auth";
export declare class JWTSession extends sidGenerator {
    salt: string;
    constructor();
    sign(payload: obj<any>): string;
    get random(): string;
    jwt(): ServerSide;
    verify(payload: string, time?: {
        days?: number;
        hours?: number;
        minutes?: number;
        seconds?: number;
    }): obj<string> | null;
    open(token: string, time?: {
        days?: number;
        hours?: number;
        minutes?: number;
        seconds?: number;
    }): ServerSide;
    save(xjwts: ServerSide): string;
    new(payload: obj<any>): string;
}
