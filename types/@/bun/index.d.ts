import { BunFile } from "bun";
export { JSONCacher } from "./json";
export declare const isFile: (path: string, data?: string) => boolean, isDir: (path: string) => boolean;
export declare const initEnv: (path: string, envPath?: string) => void;
export declare const getTLS: (dir: string) => Record<string, BunFile>;
