/*
-------------------------
TYPES
-------------------------
*/
export interface obj<T> {
  [Key: string]: T;
}

export type dict<K extends keyof any, T> = { [P in K]: T };

export type V = string | number | boolean;

/*
-------------------------
// Singleton with TypeScript decorators:
-------------------------
*/
/**
 * A decorator function that creates a singleton class from the provided constructor.
 * The singleton instance is cached and returned on subsequent calls to the constructor.
 * @param constructor - The constructor function of the class to be made a singleton.
 * @returns A new class that extends the provided constructor and implements the singleton pattern.
 */
export function Singleton<T extends { new (...args: any[]): any }>(
  constructor: T,
) {
  let instance: T;
  return class extends constructor {
    constructor(...args: any[]) {
      if (instance) {
        return instance;
      }
      super(...args);
      instance = this as any;
    }
  };
}

/**
 * A decorator function that creates a cached class from the provided constructor.
 * The class instance is cached and returned on subsequent calls to the constructor.
 * This can be useful for expensive object creation or initialization.
 * @param constructor - The constructor function of the class to be cached.
 * @returns A new class that extends the provided constructor and implements caching.
 */
export function Cached<T extends { new (...args: any[]): any }>(
  constructor: T,
) {
  return class extends constructor {
    constructor(...args: any[]) {
      super(...args);
      const cache: Map<string, any> = new Map();
      return new Proxy(this, {
        get(target, property: any) {
          const cacheKey = `__${property}`;
          if (!cache.has(cacheKey)) {
            let fn = target[property];
            if (isFN(fn)) {
              fn = function (...args: any[]) {
                const methodCacheKey = `${cacheKey}_${JSON.stringify(args)}`;
                if (!cache.has(methodCacheKey)) {
                  const result = target[property].apply(target, args);
                  cache.set(methodCacheKey, result);
                }
                return cache.get(methodCacheKey);
              };
            }
            cache.set(cacheKey, fn);
          }
          return cache.get(cacheKey);
        },
        set(target, property: string, value) {
          const cacheKey = `__${property}`;
          cache.set(cacheKey, value);
          return true;
        },
      });
    }
  };
}

export class $$ {
  static set p(a: any) {
    if (Array.isArray(a)) {
      console.log(...a);
    } else {
      console.log(a);
    }
  }
}

/**
 * A custom Map implementation that provides additional utility methods for working with objects and maps.
 *
 * @template K - The type of the keys in the map.
 * @template V - The type of the values in the map.
 */
export class Mapper<K, V> extends Map<K, V> {
  obj(obj?: object | null) {
    obj && oItems(obj).forEach(([k, v]) => this.set(k as K, v));
  }
  map(map: Map<K, V>) {
    map.forEach((v, k) => {
      this.set(k, v);
    });
  }
  ass<T>(key: K, obj: T) {
    if (!this.has(key)) this.set(key, {} as any);
    oAss(this.get(key)!, obj);
  }
}

/*
-------------------------
CONST
-------------------------
*/

export const numSequence = (length: number) =>
  Array.from({ length }, (_, ind) => ind);

const charU = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  charL = "abcdefghijklmnopqrstuvwxyz",
  nums = numSequence(10).join("");

/*
-------------------------
CONST
-------------------------
*/
export const RBYTES = new RegExp(/(\d+)(\d*)/, "m");

/*
-------------------------
Arrays
-------------------------
*/

/*
-------------------------
IS
-------------------------
*/

export const isFN = (v: any): v is Function => typeof v === "function",
  /*
  -------------------------
  -------------------------
  */
  isAsync = (v: any): v is Function => v.constructor.name === "AsyncFunction",
  isNumber = (value: any) => {
    return !isNaN(parseFloat(value)) && isFinite(value);
  },
  /*
  -------------------------
  
  -------------------------
  */
  isDict = (val: object) => {
    return typeof val === "object" && val !== null && !Array.isArray(val);
  },
  /*
  -------------------------
  -------------------------
  */
  isArraybuff = (val: any) => {
    return (
      val instanceof Uint8Array ||
      val instanceof ArrayBuffer ||
      typeof val === "string"
    );
  },
  /*
  -------------------------
  -------------------------
  */
  isClassOrId = (k: string): boolean => {
    return k.startsWith(".") || k.startsWith("#");
  },
  /*
  -------------------------
  -------------------------
  */
  isBool = (v: any) => typeof v === "boolean",
  /*
  -------------------------
  -------------------------
  */
  isStr = (v: any) => typeof v === "string",
  /*
  -------------------------
  -------------------------
  */
  isArr = (v: any) => Array.isArray(v),
  /*
  -------------------------
  -------------------------
  */
  isObj = (v: any): v is object => typeof v === "object",
  /*
  -------------------------
  -------------------------
  */
  isNum = (v: any): v is number => typeof v === "number",
  /*
  -------------------------
  -------------------------
  */
  isInt = (str: string): boolean => {
    return Number.isInteger(Number(str));
  };
/*
  -------------------------
  -------------------------
  */

// OBJECTS ------------------------------------

export const oVals = Object.values,
  oKeys = Object.keys,
  oItems = Object.entries,
  oHas = Object.hasOwn,
  oDefine = Object.defineProperty,
  oAss = Object.assign,
  oLen = (ob: object) => {
    return Object.keys(ob).length;
  };

// STRING ------------------------------------

export const strip = (str: string, charToStrip: string): string => {
    if (!str || !charToStrip) return str;
    return str.replace(
      new RegExp(`^${charToStrip}+|${charToStrip}+$`, "g"),
      "",
    );
  },
  stripOnce = (char: string, tostrip: string) =>
    char.replace(new RegExp(`^${tostrip}|${tostrip}$`, "g"), ""),
  /*
  -------------------------
  -------------------------
  */
  buffed = (str: string): Buffer => {
    return Buffer.from(str);
  },
  /*
  -------------------------
  -------------------------
  */
  hdigest = (...salt: string[]) => {
    const hmac = new Bun.CryptoHasher("sha256", getSecret());
    salt.forEach((ss) => {
      hmac.update(ss);
    });
    return hmac.digest();
  },
  /*
  -------------------------
  JSON
  -------------------------
  */
  ngify = (str: object) => JSON.stringify(str),
  sparse = (str: string) => {
    return JSON.parse(str);
  },
  /*
  -------------------------
  -------------------------
  */
  reCamel = (_case: string) => {
    if (_case.startsWith("webkit")) {
      _case = "--" + _case;
    }
    return _case.replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase();
  };

// GETTER ------------------------------------

export const getSecret = () => {
    const sk = process.env.SECRET_KEY;
    if (!sk) throw new Error("'SECRET_KEY' not found in .env file");
    return sk;
  },
  /*
  -------------------------
  -------------------------
  */
  getByteRange = (fsize: number, range: string): [number, number, number] => {
    const [start, end] = range
      .replace(/bytes=/, "")
      .split("-")
      .map((val, index) => {
        const parsed = parseInt(val, 10);
        return isNaN(parsed) ? (index === 0 ? 0 : fsize - 1) : parsed;
      });
    return [start, end, fsize];
  },
  /*
  -------------------------
  -------------------------
  */ getArgs = (params: string[], vals: string[]) => {
    return params.reduce<obj<string>>((k, v, i) => {
      k[v] = vals[i];
      return k;
    }, {});
  };

// PATH ------------------------------------

export const pathType = (
  wrd: string,
  isFinal: boolean = false,
): [any, string] => {
  if (isNumber(wrd)) {
    return [+wrd, isInt(wrd) ? "int" : "float"];
  }

  if (isFinal && wrd.includes(".")) {
    return [wrd, "file"];
  }

  if (wrd === "/") {
    return [wrd, "-"];
  }

  if (wrd.length === 36 && wrd.match(/\-/g)?.length === 4) {
    return [wrd, "uuid"];
  }

  return [wrd, "string"];
};

export function parsePath(path: string) {
  const normalizedPath = path.startsWith("/") ? path : "/" + path;
  const segments = normalizedPath.match(/(?<=\/)[^/].*?(?=\/|$)/g) ?? ["/"];

  const [parsed, args] = segments.reduce<[string[], string[]]>(
    ([pathParts, parameters], segment) => {
      if (segment.includes("<")) {
        const paramMatch = segment.match(/(?<=<)[^/].*?(?=>|$)/g);
        if (paramMatch?.length) {
          const [paramType, paramName] = paramMatch[0].split(":");
          if (paramType && paramName) {
            pathParts.push(paramType);
            parameters.push(paramName);
          }
        }
      } else {
        pathParts.push(segment === ">" ? "/" : segment);
      }
      return [pathParts, parameters];
    },
    [[], []],
  );

  if (normalizedPath.endsWith("/") && normalizedPath.length > 1) {
    parsed.push("/");
  }

  return { parsed, args };
}
// PATH ------------------------------------

export class Time {
  date: Date;
  constructor(dateMS?: number) {
    this.date = dateMS ? new Date(dateMS) : new Date();
  }
  delta(date2: number | null = null, _Date: boolean = false) {
    const TD = Time.delta(this.date.getTime(), date2);
    return _Date ? new Date(TD) : TD;
  }
  //
  timed(time?: {
    year?: number;
    month?: number;
    day?: number;
    hour?: number;
    minute?: number;
    second?: number;
  }) {
    if (!time) return this.date;

    const timeUnits = [
      ["year", "FullYear"],
      ["month", "Month"],
      ["day", "Date"],
      ["hour", "Hours"],
      ["minute", "Minutes"],
      ["second", "Seconds"],
    ] as const;

    return timeUnits.reduce((date, [unit, method]) => {
      const value = time[unit as keyof typeof time];
      return value
        ? new Date(date[`set${method}`](date[`get${method}`]() + value))
        : date;
    }, new Date(this.date));
  }

  static delta(date1: number, date2: number | null = null) {
    return date2 ? date2 - date1 : date1 - Date.now();
  }
  static get now() {
    return Date.now();
  }
}

// MAKER ------------------------------------

export const makeID = (length: number) => {
  const _chars = charU + charL;
  return Array.from({ length }, (_, i) => _chars + (i ? nums : "")).reduce(
    (acc, char) => {
      return (acc += char.charAt(Math.floor(Math.random() * char.length)));
    },
    "",
  );
};

export const rand = (min = 6, max?: number) => {
  if (!max) return Math.floor(Math.random() * min);
  return Math.round(Math.random() * (max - min) + min);
};
