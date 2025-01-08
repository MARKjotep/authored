export declare function readOnly<T extends any>(instance: T, OD: Record<string, any>): void;
export declare class $$ {
    static set p(a: any);
}
export declare class idm {
    private _c;
    private _id;
    constructor(mid?: string);
    get id(): string;
    get mid(): string;
}
export declare const getSecret: () => string, getByteRange: (fsize: number, range: string) => [number, number, number], getArgs: (params: string[], vals: string[]) => Record<string, string>;
