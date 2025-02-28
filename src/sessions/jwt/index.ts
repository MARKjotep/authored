import { CryptoHasher } from "bun";
import { getSecret, obj } from "../../@";
import { sign, verify } from "jsonwebtoken";
import { randomBytes } from "node:crypto";
import { sidGenerator } from "../../auth/generator";
import { ServerSide } from "../../auth/server";

export class JWTSession extends sidGenerator {
  salt: string;
  constructor() {
    super("salty_jwt");
    this.salt = "salty_jwt";
  }
  sign(payload: obj<any>) {
    const options = {
      issuer: this.salt, // Issuer of the token
    };
    const datax = {
      data: payload,
    };

    return sign(datax, getSecret(), options);
  }
  get random() {
    const options = {
      issuer: this.salt, // Issuer of the token
    };
    const datax = {
      data: hashedToken(),
    };
    return sign(datax, getSecret(), options);
  }
  jwt() {
    //
    const rid = this.generate();
    return new ServerSide(rid).session;
  }
  verify(
    payload: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ): obj<string> | null {
    try {
      const ever = verify(payload, getSecret());

      if (ever) {
        const { data, iat, iss } = ever as any;
        if (iss == this.salt) {
          if (time) {
            const { days, hours, minutes, seconds } = time;
            let endD = new Date(iat * 1000);
            if (days) {
              endD = new Date(endD.setDate(endD.getDate() + days));
            } else if (hours) {
              endD = new Date(endD.setHours(endD.getHours() + hours));
            } else if (minutes) {
              endD = new Date(endD.setMinutes(endD.getMinutes() + minutes));
            } else if (seconds) {
              endD = new Date(endD.setSeconds(endD.getSeconds() + seconds));
            }
            if (endD.getTime() - Date.now() > 0) {
              return data as obj<string>;
            }
          } else {
            return data as obj<string>;
          }
        }
      }
    } catch (e) {}

    return null;
  }
  open(
    token: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ): ServerSide {
    if (token) {
      const tv = this.verify(token, time);
      if (tv) {
        return new ServerSide(token, tv, true).session;
      }
    }

    return this.jwt();
  }
  save(xjwts: ServerSide) {
    const data = xjwts.data;
    if ("access_token" in data) {
      delete data["access_token"];
    }
    return this.sign(data);
  }
  new(payload: obj<any>) {
    return this.sign(payload);
  }
}

function hashedToken(len = 64) {
  return new CryptoHasher("sha256").update(randomBytes(len)).digest("hex");
}
