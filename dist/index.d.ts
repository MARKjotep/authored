import { Client } from 'pg';

declare class Signator {
    salt: string;
    constructor(salt: string);
    getSignature(val: string): string;
    deriveKey(): Buffer;
    sign(val: string): string;
    unsign(signedVal: string): boolean;
    loadUnsign(vals: string): string | undefined;
    verifySignature(val: string, sig: string): boolean;
}

declare class sidGenerator {
    signer: Signator;
    constructor(salt: string);
    generate(len?: number): string;
}

type obj<T> = Record<string, T>;

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
declare class ServerSide extends callBack {
    sid: string;
    [Key: string]: any;
    modified: boolean;
    private readonly readOnly;
    constructor(sid?: string, initial?: obj<string>, readonly?: boolean);
    get session(): ServerSide;
}

declare class AuthInterface extends sidGenerator {
    config: authConfig;
    constructor(config: authConfig, salt?: string);
    openSession(sid?: string, readonly?: boolean): Promise<ServerSide>;
    fetchSession(sid: string, readonly?: boolean): Promise<ServerSide>;
    saveSession(sesh: ServerSide, X?: Headers, deleteMe?: boolean): Promise<void>;
    get new(): ServerSide;
    get readonly(): ServerSide;
    get getExpiration(): string | null;
    setCookie(xsesh: ServerSide, life: Date | number, _sameSite?: string): string;
    loadHeader(req: any, readonly?: boolean): Promise<ServerSide>;
}

interface bs$1 {
    f_timed?: number;
    [key: string]: string | undefined | boolean | number;
}
interface ffcache {
    [key: string]: string | undefined | boolean | number;
    f_timed?: number;
    data: string;
    life: number;
}
declare class FSCached<T extends bs$1> {
    path: string;
    data: Map<any, T>;
    constructor(folderpath: string);
    init(val: string): Promise<T | null>;
    checkLast(time: number): Promise<boolean>;
    get(val: string | undefined): Promise<T | null>;
    set(val: string, data: T): Promise<void>;
    delete(key: string): Promise<void>;
}

declare class FSession extends ServerSide {
}
declare class FSInterface extends AuthInterface {
    isJWT: boolean;
    cacher: FSCached<ffcache>;
    side: typeof FSession;
    constructor(config: authConfig, cacherpath?: string, isJWT?: boolean);
    life(key: string, lstr: number): boolean;
    fetchSession(sid: string, readonly?: boolean): Promise<ServerSide>;
    saveSession(sesh: ServerSide, X?: Headers, deleteMe?: boolean): Promise<void>;
}

interface bs {
    f_timed?: number;
    [key: string]: string | undefined | boolean | number;
}
declare class PGCache<T extends bs> {
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

declare class PostgreSession extends ServerSide {
}
interface sesh_db {
    sid: string;
    data: string;
    expiration: string;
    f_timed?: number;
    [key: string]: string | undefined | boolean | number;
}
declare class PGInterface extends AuthInterface {
    sclass: typeof ServerSide;
    client: Client;
    pgc: PGCache<sesh_db>;
    constructor(client: Client, config: authConfig);
    fetchSession(sid: string): Promise<ServerSide>;
    saveSession(xsesh: ServerSide, rsx?: any, deleteMe?: boolean, sameSite?: string): Promise<void>;
}

declare class JWTSession extends sidGenerator {
    salt: string;
    constructor();
    sign(payload: obj<any>): string;
    get random(): string;
    jwt(): ServerSide;
    verify(payload: string, time?: {
        days?: number;
        hours?: number;
        minutes?: number;
        seconds?: number;
    }): obj<string> | null;
    open(token: string, time?: {
        days?: number;
        hours?: number;
        minutes?: number;
        seconds?: number;
    }): ServerSide;
    save(xjwts: ServerSide): string;
    new(payload: obj<any>): string;
}

type dbs = "fs" | "postgres";
interface authConfig {
    COOKIE_NAME: string;
    COOKIE_DOMAIN: string;
    COOKIE_PATH: string;
    COOKIE_HTTPONLY: boolean;
    COOKIE_SECURE: boolean;
    REFRESH_EACH_REQUEST: boolean;
    COOKIE_SAMESITE: string;
    KEY_PREFIX: string;
    PERMANENT: boolean;
    USE_SIGNER: boolean;
    ID_LENGTH: number;
    FILE_THRESHOLD: number;
    LIFETIME: number;
    MAX_COOKIE_SIZE: number;
    INTERFACE: dbs;
    STORAGE: string;
    JWT_STORAGE: string;
    JWT_LIFETIME: number;
}
declare class Auth {
    postgresClient?: Client;
    config: authConfig;
    constructor({ type, dir }?: {
        type?: dbs;
        dir?: string;
    });
    initStorage(path: string): this;
    get session(): AuthInterface;
    get jwt(): FSInterface;
}
declare class Session {
    session: AuthInterface;
    jwt: AuthInterface;
    jwtInt: JWTSession;
    init(sh: Auth): void;
}

export { Auth, AuthInterface, FSCached, FSInterface, FSession, PGCache, PGInterface, PostgreSession, ServerSide, Session, type authConfig };
