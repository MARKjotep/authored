export declare function Singleton<T extends {
    new (...args: any[]): any;
}>(constructor: T): {
    new (...args: any[]): {
        [x: string]: any;
    };
} & T;
export declare function Cached<T extends {
    new (...args: any[]): any;
}>(constructor: T): {
    new (...args: any[]): {
        [x: string]: any;
    };
} & T;
