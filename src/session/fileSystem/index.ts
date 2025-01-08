import { Time } from "../../@";
import { authConfig, AuthInterface } from "../../auth";
import { ServerSide } from "../../auth";
import { ffcache, FSCached } from "./cache";

export { FSCached };

export class FSession extends ServerSide {}

export class FSInterface extends AuthInterface {
  cacher: FSCached<ffcache>;
  side = FSession;

  constructor(
    config: authConfig,
    cacherpath = ".sessions",
    public isJWT: boolean = false,
  ) {
    super(config);
    this.cacher = new FSCached(cacherpath);
  }

  life(key: string, lstr: number) {
    const { LIFETIME, JWT_LIFETIME } = this.config;
    const NT = new Time(lstr).timed({
      day: this.isJWT ? JWT_LIFETIME : LIFETIME,
    });
    if (NT.getTime() - new Date().getTime() > 0) {
      return true;
    } else {
      this.cacher.delete(key);
      return false;
    }
  }

  async fetchSession(sid: string, readonly?: boolean): Promise<ServerSide> {
    const prefs = this.config.KEY_PREFIX + sid;
    const dt = await this.cacher.get(prefs);
    let _data = {};
    if (dt) {
      let isL = true;
      if ("life" in dt) {
        isL = this.life(prefs, dt.life);
      }
      _data = isL ? JSON.parse(dt.data) : {};
    }
    return new this.side(sid, _data, readonly).session;
  }

  async saveSession(
    sesh: ServerSide,
    X?: Headers,
    deleteMe: boolean = false,
  ): Promise<void> {
    const sCookie = (life: 0 | Date) => {
      if (X) {
        const cookie = this.setCookie(sesh, life);
        if (X) {
          X.set("Set-Cookie", cookie);
        }
      }
    };
    const prefs = this.config.KEY_PREFIX + sesh.sid;
    if (!sesh.length) {
      if (!sesh.new && (sesh.modified || deleteMe)) {
        this.cacher.delete(prefs);
        sCookie(0);
      }
      return;
    }

    if (sesh.new && sesh.modified) {
      const life = new Time().timed({ day: this.config.LIFETIME });
      const data = JSON.stringify(sesh.data);
      await this.cacher.set(prefs, {
        data,
        life: Time.now,
      });
      sCookie(life);
    }

    return;
  }
}
