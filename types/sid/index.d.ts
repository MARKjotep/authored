import { Signator } from "../signer";
export declare class sidGenerator {
    signer: Signator;
    constructor(salt: string);
    generate(len?: number): string;
}
export declare function decodeSID(str: string): string;
