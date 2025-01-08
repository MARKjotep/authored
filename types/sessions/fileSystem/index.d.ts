import { authConfig, AuthInterface } from "../../auth";
import { ServerSide } from "../../auth";
import { ffcache, FSCached } from "./cache";
export { FSCached };
export declare class FSession extends ServerSide {
}
export declare class FSInterface extends AuthInterface {
    isJWT: boolean;
    cacher: FSCached<ffcache>;
    side: typeof FSession;
    constructor(config: authConfig, cacherpath?: string, isJWT?: boolean);
    life(key: string, lstr: number): boolean;
    fetchSession(sid: string, readonly?: boolean): Promise<ServerSide>;
    saveSession(sesh: ServerSide, X?: Headers, deleteMe?: boolean): Promise<void>;
}
