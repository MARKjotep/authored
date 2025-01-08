import { AuthInterface } from "./interface";
import { authConfig, dbs } from "./config";
export { ServerSide } from "./server";
export { AuthInterface, authConfig, dbs };
export declare class Signator {
    salt: string;
    constructor(salt: string);
    getSignature(val: string): string;
    deriveKey(): Buffer;
    sign(val: string): string;
    unsign(signedVal: string): boolean;
    loadUnsign(vals: string): string | undefined;
    verifySignature(val: string, sig: string): boolean;
}
export declare class sidGenerator {
    signer: Signator;
    constructor(salt: string);
    generate(len?: number): string;
}
export declare function decodeSID(str: string): string;
