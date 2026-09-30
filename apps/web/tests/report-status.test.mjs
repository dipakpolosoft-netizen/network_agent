import assert from "node:assert/strict";
import { test } from "node:test";

import { scanCoverageNotice, scanResultCoverage } from "../src/lib/report-status.ts";

test("terminal command failure does not count missing host results as evidence", () => {
  assert.deepEqual(
    scanResultCoverage({ total: 109, results: [{ device_id: "a" }, { device_id: "b" }, { device_id: "c" }, { device_id: "d" }] }),
    { saved: 4, missing: 105, percent: 4 },
  );
});

test("running export is identified as an in-progress snapshot", () => {
  assert.match(scanCoverageNotice({ status: "running", total: 5, completed: 2, failed: 0, cancelled: 0 }), /2 of 5 targets completed/);
  assert.match(scanCoverageNotice({ status: "cancelling", total: 5, completed: 2, failed: 0, cancelled: 0 }), /Download again/);
});

test("failed or partial coverage never reads as a clean scan", () => {
  const notice = scanCoverageNotice({ status: "partial", total: 3, completed: 1, failed: 1, cancelled: 1 });
  assert.match(notice, /Coverage is incomplete/);
  assert.match(notice, /zero findings do not establish/);
  assert.match(scanCoverageNotice({ status: "completed", total: 3, completed: 2, failed: 1, cancelled: 0 }), /Coverage is incomplete/);
  assert.equal(scanCoverageNotice({ status: "completed", total: 3, completed: 3, failed: 0, cancelled: 0 }), null);
});
