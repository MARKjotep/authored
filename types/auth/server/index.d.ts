import { obj } from "../../@";
declare class callBack {
    [Key: string]: any;
    data: obj<string>;
    modified: boolean;
    new: boolean;
    length: number;
    constructor(initial?: obj<string>);
    set(target: any, prop: string, val: string): boolean;
    get(target: any, prop: string): any;
    has(target: any, prop: string): boolean;
    deleteProperty(target: any, val: string): boolean;
}
export declare class ServerSide extends callBack {
    sid: string;
    [Key: string]: any;
    modified: boolean;
    private readonly readOnly;
    constructor(sid?: string, initial?: obj<string>, readonly?: boolean);
    get session(): ServerSide;
}
export {};
