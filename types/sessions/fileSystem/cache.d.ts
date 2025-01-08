interface bs {
    f_timed?: number;
    [key: string]: string | undefined | boolean | number;
}
export interface ffcache {
    [key: string]: string | undefined | boolean | number;
    f_timed?: number;
    data: string;
    life: number;
}
export declare class FSCached<T extends bs> {
    path: string;
    data: Map<any, T>;
    constructor(folderpath: string);
    init(val: string): Promise<T | null>;
    checkLast(time: number): Promise<boolean>;
    get(val: string | undefined): Promise<T | null>;
    set(val: string, data: T): Promise<void>;
    delete(key: string): Promise<void>;
}
export {};
