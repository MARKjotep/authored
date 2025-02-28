import { authConfig } from "../..";
import { obj, setCookie } from "../../@";
import { sidGenerator } from "../generator";
import { ServerSide } from "../server";


export class AuthInterface extends sidGenerator {
  constructor(
    public config: authConfig,
    salt?: string,
  ) {
    super(salt ?? "salty");
  }
  async openSession(sid?: string, readonly?: boolean): Promise<ServerSide> {
    if (sid && this.signer.unsign(sid))
      return await this.fetchSession(sid, readonly);
    return this.new;
  }
  async fetchSession(sid: string, readonly?: boolean): Promise<ServerSide> {
    return this.new;
  }
  async saveSession(
    sesh: ServerSide,
    X?: Headers,
    deleteMe: boolean = false,
  ): Promise<void> {
    return;
  }
  get new() {
    return new ServerSide(this.generate(), {}).session;
  }
  get readonly() {
    return new ServerSide(this.generate(), {}, true).session;
  }
  get getExpiration(): string | null {
    const now = new Date();
    const lifet = this.config.LIFETIME;
    return now.setDate(now.getDate() + lifet).toString();
  }
  setCookie(xsesh: ServerSide, life: Date | number, _sameSite = "") {
    let sameSite: string | null = null;
    let xpire: obj<any> = {};
    if (this.config.COOKIE_SAMESITE) {
      sameSite = this.config.COOKIE_SAMESITE;
    }

    if (_sameSite) {
      sameSite = _sameSite;
    }
    if (life === 0) {
      xpire.maxAge = life.toString();
    } else {
      xpire.expires = life;
    }

    return setCookie(this.config.COOKIE_NAME!, xsesh.sid, {
      domain: "",
      path: this.config.COOKIE_PATH,
      httpOnly: this.config.COOKIE_HTTPONLY,
      secure: this.config.COOKIE_SECURE,
      sameSite: sameSite,
      ...xpire,
    });
  }
  async loadHeader(req: any, readonly?: boolean) {
    const CK = async (ck?: string) => {
      let sid: string | undefined = "";
      if (ck) {
        let cc = ck.split(";").reduce<obj<string>>((ob, d) => {
          const [key, val] = d.trim().split(/=(.*)/s);
          ob[key] = val;
          return ob;
        }, {});
        sid = cc.session;
      }

      const prefs = sid;
      return await this.openSession(prefs, readonly);
    };
    let RH = req.headers;
    if (RH) {
      if ("get" in RH) {
        return await CK(RH.get("cookie"));
      } else if ("cookie" in RH) {
        return await CK(RH.cookie);
      }
    }

    return this.new;
  }
}
