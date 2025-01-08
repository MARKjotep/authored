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
