export declare class Mapper<K, V> extends Map<K, V> {
    obj(obj?: object | null): void;
    map(map: Mapper<K, V>): void;
    ass<T>(key: K, obj: T): void;
    lacks(key: K): boolean;
    init(key: K, val: V): V | undefined;
}
export declare const oVals: {
    <T>(o: {
        [s: string]: T;
    } | ArrayLike<T>): T[];
    (o: {}): any[];
}, oKeys: {
    (o: object): string[];
    (o: {}): string[];
}, oItems: {
    <T>(o: {
        [s: string]: T;
    } | ArrayLike<T>): [string, T][];
    (o: {}): [string, any][];
}, oHas: (o: object, v: PropertyKey) => boolean, oFreeze: {
    <T extends Function>(f: T): T;
    <T extends {
        [idx: string]: U | null | undefined | object;
    }, U extends string | bigint | number | boolean | symbol>(o: T): Readonly<T>;
    <T>(o: T): Readonly<T>;
}, oDefine: <T>(o: T, p: PropertyKey, attributes: PropertyDescriptor & ThisType<any>) => T, oAss: {
    <T extends {}, U>(target: T, source: U): T & U;
    <T extends {}, U, V>(target: T, source1: U, source2: V): T & U & V;
    <T extends {}, U, V, W>(target: T, source1: U, source2: V, source3: W): T & U & V & W;
    (target: object, ...sources: any[]): any;
}, oLen: (ob: object) => number;
export declare const keyInMap: <T>(id: string, map: Mapper<string, any>) => T;
export declare const keyInMapArray: <T>(id: string, map: Mapper<string, any>) => T;
type Changes = {
    added: Record<string, any>;
    removed: Record<string, any>;
    modified: Record<string, {
        old: any;
        new: any;
    }>;
};
export declare const compareObjects: <T extends object>(oldObj: T, newObj: T | any) => Changes;
export declare const objectUdpated: (changes: Changes) => boolean;
export {};
