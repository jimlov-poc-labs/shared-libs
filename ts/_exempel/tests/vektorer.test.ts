import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { striktPort } from "../src/index.js";

interface Fall {
  namn: string;
  in: string;
  ut: number | null;
}

const fil = new URL("../../../spec/_exempel/vektorer.json", import.meta.url);
const fall = (JSON.parse(readFileSync(fil, "utf-8")) as { fall: Fall[] }).fall;

describe("delad testvektor", () => {
  it.each(fall)("$namn", (f) => {
    expect(striktPort(f.in)).toBe(f.ut);
  });
  it("vektorfilen är inte tom", () => {
    expect(fall.length).toBeGreaterThanOrEqual(10);
  });
});
