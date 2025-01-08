export declare const pathType: (wrd: string, isFinal?: boolean) => [any, string];
export declare const parsePath: (path: string) => {
    parsed: string[];
    args: string[];
};
export declare class MinStorage {
    readonly path: string;
    readonly parsed: string[];
    readonly args: string[];
    constructor(path: string);
}
export declare class Storage<T extends MinStorage> {
    private _storage;
    set(min: T): void;
    get(path: string): [T | undefined, Record<string, string>];
}
export declare class SymStorage<T extends MinStorage> {
    [k: symbol]: Storage<T>;
    constructor(...sym: symbol[]);
    get(sym: symbol): Storage<T>;
}
