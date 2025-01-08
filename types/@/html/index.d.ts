import { obj } from "../types";
import { Mapper } from "../obj";
type meta<T> = {
    charset?: T;
    content?: T;
    "http-equiv"?: T;
    name?: T;
    property?: T;
    media?: T;
    url?: T;
};
type link<T> = {
    href?: T;
    hreflang?: T;
    media?: T;
    referrerpolicy?: T;
    rel?: "stylesheet" | "icon" | "manifest" | T;
    sizes?: T;
    title?: T;
    type?: T;
    as?: T;
    crossorigin?: T;
};
type impmap = {
    imports?: obj<string>;
    scopes?: obj<string>;
    integrity?: obj<string>;
};
type script<T> = {
    async?: T;
    crossorigin?: T;
    defer?: T;
    integrity?: T;
    nomodule?: T;
    referrerpolicy?: T;
    src?: T;
    type?: "text/javascript" | T;
    id?: T;
    importmap?: impmap;
    body?: T;
};
type base<T> = {
    href?: T;
    target?: "_blank" | "_parent" | "_self" | "_top";
};
export interface headAttr {
    title?: string;
    base?: base<string>[];
    meta?: meta<string>[];
    link?: link<string>[];
    script?: script<string>[];
}
export type headType = Mapper<string, any>;
export declare class _htmlHead {
    private _head;
    constructor(initial?: headType);
    set head(heads: headAttr);
    get head(): headType;
}
export declare const getHead: (v: headType) => string;
export declare class htmlHead {
    htmlHead: headType;
    head: (heads?: headAttr) => void;
    constructor();
}
interface cookieSet {
    maxAge?: Date | number;
    expires?: Date | string | number;
    path?: string | null;
    domain?: string;
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: string | null;
    sync_expires?: boolean;
    max_size?: number;
}
export declare const setCookie: (key: string, value: string | undefined, { maxAge, expires, path, domain, secure, httpOnly, sameSite }: cookieSet) => string;
export {};
