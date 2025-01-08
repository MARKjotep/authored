export type V = string | number | boolean;
export type obj<T> = Record<string, T>;
export type dict<K extends keyof any, T> = Record<K, T>;
