import assert from "node:assert/strict";
import test from "node:test";

import { nvdDataAge } from "../src/lib/nvd-evidence.ts";

const now = Date.parse("2026-09-28T12:00:00Z");

test("provider age is distinct from assessment time", () => {
  assert.equal(nvdDataAge("2026-09-27T12:00:00Z", now), "24 hr old");
  assert.equal(nvdDataAge("2026-09-28T11:30:00Z", now), "30 min old");
  assert.equal(nvdDataAge("2026-09-25T12:00:00Z", now), "3 d old");
  assert.equal(nvdDataAge(null, now), "age unavailable");
});
