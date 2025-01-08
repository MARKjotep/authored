import { Client } from "pg";

interface bs {
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}

/*
-------------------------
Postgres
-------------------------
*/

// Single query --
export class PGCache<T extends bs> {
  client: Client;
  query: string;
  f_timed: number;
  data: Map<any, T>;
  key: string;
  constructor(client: Client, key: string, query: string) {
    this.query = query;
    this.key = key;
    this.f_timed = Date.now();
    this.data = new Map();
    this.client = client;
  }
  async init(val: string): Promise<T | null> {
    const TQ = await this.client.query({
      text: this.query + ` where ${this.key} = $1`,
      values: [val],
    });
    // Delete keys with no value
    for (const [k, v] of this.data) {
      if (!v) {
        this.data.delete(k);
      }
    }
    if (TQ.rowCount) {
      const tr = TQ.rows[0];
      tr.f_timed = Date.now();
      this.data.set(val, tr);
      return tr;
    } else {
      this.data.set(val, null as any);
      return null;
    }
  }
  async checkLast(time: number) {
    const xl = new Date(time);
    xl.setMinutes(xl.getMinutes() + 15);
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
  async set(data: T) {
    if (this.key in data) {
      data.f_timed = Date.now();
      this.data.set(data[this.key], data);
    }
  }
  async delete(key: string) {
    this.data.delete(key);
  }
}
