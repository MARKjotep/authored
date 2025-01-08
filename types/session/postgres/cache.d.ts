import { Client } from "pg";
interface bs {
    f_timed?: number;
    [key: string]: string | undefined | boolean | number;
}
export declare class PGCache<T extends bs> {
    client: Client;
    query: string;
    f_timed: number;
    data: Map<any, T>;
    key: string;
    constructor(client: Client, key: string, query: string);
    init(val: string): Promise<T | null>;
    checkLast(time: number): Promise<boolean>;
    get(val: string | undefined): Promise<T | null>;
    set(data: T): Promise<void>;
    delete(key: string): Promise<void>;
}
export {};
