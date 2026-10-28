// SPDX-License-Identifier: MIT
import { describe, expect, it } from "vitest";

import { address, localInput, me } from "../src/calendar/model.js";
import { LEVELS, formatSize, level, sortNodes } from "../src/files/model.js";
import { formatAddresses, parseAddresses } from "../src/mail/model.js";

describe("addresses", () => {
  it("are read and written back", () => {
    const list = parseAddresses('Bob <bob@firma.example>, carol@example.org; "Dave D." <dave@example.org>');
    expect(list).toEqual([
      { name: "Bob", email: "bob@firma.example" },
      { name: null, email: "carol@example.org" },
      { name: "Dave D.", email: "dave@example.org" },
    ]);
    expect(formatAddresses(list)).toBe("Bob <bob@firma.example>, carol@example.org, Dave D. <dave@example.org>");
  });
});

describe("calendar helpers", () => {
  it("find the user among the participants", () => {
    const event = {
      id: "e",
      calendarIds: {},
      start: "2026-11-02T09:00:00",
      accountId: "a",
      participants: { p1: { calendarAddress: "mailto:Bob@Firma.example" }, p2: { calendarAddress: "mailto:carol@example.org" } },
    };
    expect(me(event, ["bob@firma.example"])?.[0]).toBe("p1");
    expect(address({ calendarAddress: "mailto:carol@example.org" })).toBe("carol@example.org");
    expect(localInput(new Date(2026, 10, 2, 9, 5))).toBe("2026-11-02T09:05");
  });
});

describe("file helpers", () => {
  it("show sizes and sort directories first", () => {
    expect(formatSize(0, "en-GB")).toBe("0 B");
    expect(formatSize(1234, "en-GB")).toBe("1.2 kB");
    expect(formatSize(56_700_000, "de-DE")).toBe("56,7 MB");
    expect(formatSize(123_400_000, "en-GB")).toBe("123 MB");
    const node = (type: "Directory" | "File", name: string) => ({ "@type": type, id: name, parentId: null, name, modified: "" });
    const sorted = sortNodes([node("File", "b"), node("Directory", "z"), node("File", "a")], "en-GB");
    expect(sorted.map((entry) => entry.name)).toEqual(["z", "a", "b"]);
  });

  it("name the level of rights", () => {
    expect(level(LEVELS.read)).toBe("read");
    expect(level(LEVELS.edit)).toBe("edit");
    expect(level(LEVELS.full)).toBe("full");
    expect(level({ ...LEVELS.read, mayAddChildren: true })).toBe("edit");
  });
});
