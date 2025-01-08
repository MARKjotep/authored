export declare const RBYTES: RegExp;
export declare const numSequence: (length: number) => number[];
export declare const strip: (str: string, charToStrip: string) => string, stripOnce: (char: string, tostrip: string) => string, buffed: (str: string) => Buffer, hdigest: (...salt: string[]) => Buffer, ngify: (str: object) => string, sparse: (str: string) => any, reCamel: (_case: string) => string;
export declare const makeID: (length: number) => string;
export declare const rand: (min?: number, max?: number) => number;
export declare const strDecode: (str: any) => string;
