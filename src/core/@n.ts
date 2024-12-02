import { mkdirSync, writeFileSync } from "node:fs";

export const isFile = (path: string, data: string = "") => {
    try {
      writeFileSync(path, data, { flag: "wx" });
      return true;
    } catch (error) {
      return false;
    }
  } /*
-------------------------
-------------------------
*/,
  isDir = (path: string) => {
    mkdirSync(path, { recursive: true });
    return true;
  };
