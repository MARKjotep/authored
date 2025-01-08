interface fs {
    [key: string]: string | undefined | boolean | number;
}
export declare class JSONCacher<T extends fs> {
    fs: string;
    f_timed: number;
    data: Map<any, T>;
    key: string;
    dir: string;
    constructor({ dir, fs, key }: {
        dir: string;
        fs: string;
        key: string;
    });
    init(): Promise<void>;
    get(val: string | undefined): Promise<T | null>;
    set(data: T): Promise<void>;
    delete(key: string): Promise<void>;
    json(): Promise<unknown[]>;
}
export {};
