import { file, gunzipSync, gzipSync, write } from "bun";
import { promises as fr } from "node:fs";
import { decodeSID } from "../../auth";
import { strDecode } from "../../@";
import { isFile } from "../../@/bun";

interface bs {
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}

// Cache the folder contents in JSON
export interface ffcache {
  [key: string]: string | undefined | boolean | number;
  f_timed?: number;
  data: string;
  life: number;
}

export class FSCached<T extends bs> {
  path: string;
  data: Map<any, T>;
  constructor(folderpath: string) {
    this.data = new Map();
    this.path = folderpath + "/";
  }
  async init(val: string): Promise<T | null> {
    const fname = decodeSID(val);
    const fpath = this.path + fname;

    const FL = file(fpath);

    if (await FL.exists()) {
      const data = await FL.arrayBuffer();
      try {
        const GX = JSON.parse(strDecode(gunzipSync(data)));
        GX.f_timed = Date.now();
        this.data.set(fname, GX);
        return GX;
      } catch (error) {}
    }
    return null;
  }
  async checkLast(time: number) {
    const xl = new Date(time);
    xl.setMinutes(xl.getMinutes() + 60);
    if (xl.getTime() < Date.now()) {
      return true;
    }
    return false;
  }
  async get(val: string | undefined): Promise<T | null> {
    if (val) {
      const hdat = this.data.get(val);
      if (hdat == undefined) {
        return await this.init(val);
      } else {
        if (hdat && "f_timed" in hdat) {
          const atv = await this.checkLast(hdat.f_timed!);
          if (atv) {
            return await this.init(val);
          }
        }
        return hdat;
      }
    }
    return null;
  }
  async set(val: string, data: T) {
    const fname = decodeSID(val);
    const fpath = this.path + fname;

    isFile(fpath, "");
    await write(fpath, gzipSync(JSON.stringify(data)));
    data.f_timed = Date.now();
    this.data.set(val, data);
  }
  async delete(key: string) {
    const fname = decodeSID(key);
    this.data.delete(fname);
    const fpath = this.path + fname;
    file(fpath)
      .exists()
      .then(async (e) => {
        await fr.unlink(fpath);
      })
      .catch();
  }
}
