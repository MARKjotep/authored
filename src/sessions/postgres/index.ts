import { Client } from "pg";
import { AuthInterface } from "../../auth/interface";
import { ServerSide } from "../../auth/server";
import { PGCache } from "./cache";
import { Time } from "../../@";
import { authConfig } from "../..";

export { PGCache };

export class PostgreSession extends ServerSide {}

interface sesh_db {
  sid: string;
  data: string;
  expiration: string;
  f_timed?: number;
  [key: string]: string | undefined | boolean | number;
}

export class PGInterface extends AuthInterface {
  sclass: typeof ServerSide = PostgreSession;
  client: Client;
  pgc: PGCache<sesh_db>;
  constructor(client: Client, config: authConfig) {
    super(config);
    this.client = client;
    this.pgc = new PGCache<sesh_db>(client, "sid", `SELECT * FROM session`);
  }
  async fetchSession(sid: string) {
    const prefs = this.config.KEY_PREFIX + sid;
    const itms = await this.pgc.get(prefs);
    let data = {};
    if (itms) {
      data = JSON.parse(itms.data);
    }
    return new this.sclass(sid, data).session;
  }
  async saveSession(
    xsesh: ServerSide,
    rsx?: any,
    deleteMe?: boolean,
    sameSite: string = "",
  ): Promise<void> {
    const prefs = this.config.KEY_PREFIX + xsesh.sid;
    if (!Object.entries(xsesh.data).length) {
      if (xsesh.modified || deleteMe) {
        if (rsx) {
          await this.client.query({
            text: `DELETE FROM session WHERE sid = $1`,
            values: [prefs],
          });

          await this.pgc.delete(prefs);
          const cookie = this.setCookie(xsesh, 0);
          rsx.header = { "Set-Cookie": cookie };
        }
      }
      return;
    }

    const life = new Time().timed({ day: this.config.LIFETIME });
    const data = JSON.stringify(xsesh.data);

    if (rsx) {
      const expre = this.getExpiration;
      await this.client.query({
        text: `INSERT INTO session(sid, data, expiration) VALUES($1, $2, $3)`,
        values: [prefs, data, expre ? expre : null],
      });
      await this.pgc.set({
        sid: prefs,
        data: data,
        expiration: expre ?? "",
        life: Time.now,
      });
      const cookie = this.setCookie(xsesh, life);
      rsx.header = { "Set-Cookie": cookie };
    }
  }
}
