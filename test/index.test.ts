import { Auth, FSInterface, ServerSide } from "../src";
import { describe, it, expect } from "bun:test";
import { $$ } from "../src/@";
import { config } from "dotenv";

config();

describe("Auth", () => {
  it("should create an Auth instance", () => {
    const auth = new Auth();
    expect(auth).toBeInstanceOf(Auth);
  });

  it("should update storage directory", () => {
    const auth3 = new Auth({ dir: "./hello" });

    expect(auth3.config.STORAGE).toBe("./hello/.sessions");
  });

  it("should instance of File System Interface", () => {
    const auth1 = new Auth();

    expect(auth1.session).toBeInstanceOf(FSInterface);
  });
});

describe("Session", () => {
  const { session, jwt } = new Auth();

  const newSession = session.new;
  it("should be intance of ServerSide", () => {
    expect(newSession).toBeInstanceOf(ServerSide);
  });

  it("should have 1 data and be new & modified", () => {
    newSession.nice = "lol";
    expect(newSession.length).toBe(1);
    expect(newSession.modified).toBe(true);
    expect(newSession.new).toBe(true);
  });

  it("should be removed and undo modification", () => {
    delete newSession.nice;
    expect(newSession.length).toBe(0);
    expect(newSession.modified).toBe(true);
    expect(newSession.new).toBe(true);
  });

  let sid = "";
  it("should be saved locally", async () => {
    newSession.hello = "world";
    expect(newSession.hello).toBe("world");

    const header = new Headers();
    await session.saveSession(newSession, header);
    expect(header.has("set-cookie")).toBe(true);
    sid = newSession.sid;
  });

  it("should be able to open SID", async () => {
    const sside = await session.openSession(sid);

    expect(sside.new).toBe(false);
    expect(sside.modified).toBe(false);
    expect(sside.hello).toBe("world");
  });

  it("should return new if session is not found or expired", async () => {
    const sside = await session.openSession(sid + "hello");

    expect(sside.new).toBe(true);
    expect(sside.length).toBe(0);
  });

  it("should be able to delete session if data is removed", async () => {
    const sside = await session.openSession(sid);

    delete sside.hello;
    expect(sside.modified).toBe(true);
    expect(sside.length).toBe(0);

    const header = new Headers();
    await session.saveSession(sside, header);
    expect(header.has("set-cookie")).toBe(true);
  });
});
