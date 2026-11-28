#!/usr/bin/env node
// Swift merge gate for run errors and timeouts: every one must have a ledger entry (mutation-run-errors.json) with a proof. A crash
// mutant races: whether the test thread reports an assertion failure before the process dies varies between runs, so for EVERY entry the
// run errors (n) plus the mutants that a test plainly decided in this run (c: status KILLED, or a TRAP attributed to a test; a trap with no
// test, such as a crash while listing, stays an error) must equal the multiplicity, and n may not exceed it. A survivor or an absent
// mutant in the missing place, an unlisted run error and an entry without a proof all fail.
//   node runerr-gate.mjs <reports dir> <mut-results dir> <ledger json> <expected report count>
//   node runerr-gate.mjs --selftest
import fs from 'node:fs';
import path from 'node:path';

const key = (m) => [m.file, m.text, m.mutant].join(' | ');

export function judge(got, results, led) {
  const errors = [];
  const have = new Map(); for (const m of got) have.set(key(m), (have.get(key(m)) || 0) + 1);
  const killed = (e) => results.filter((r) => (r.status === 'KILLED' || (r.status === 'TRAP' && r.trap && r.trap.test)) && r.file === e.file && `${r.op} => ${r.repl}` === e.mutant && String(r.orig || '').trim() === e.text.trim()).length;
  const used = new Set();
  for (const e of led) {
    if (!e.reason || e.reason.length < 40) errors.push(`run-error ledger entry without a proof (reason under 40 characters): ${key(e)}`);
    const n = have.get(key(e)) || 0, k = e.multiplicity || 1;
    if (n !== k) {
      const c = n < k ? killed(e) : 0;
      if (!(n < k && n + c === k)) errors.push(`run-error ledger entry covers ${k}, the run has ${n} and ${c} decided by a test: ${key(e)}`);
    }
    used.add(key(e));
  }
  for (const m of got) if (!used.has(key(m))) errors.push(`UNPROVEN run error, no assertion decided it: ${key(m)} (${m.evidence})`);
  return errors;
}

function walk(dir, re, f) { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p, re, f); else if (re.test(e.name)) f(p); } }

function selftest() {
  const m = { file: 'S/x.swift', text: 'r[i + 4] = carry', mutant: '4->5 => r[i + 5] = carry', evidence: 'signal 11' };
  const res = (status, trap) => [{ file: 'S/x.swift', op: '4->5', repl: 'r[i + 5] = carry', orig: 'r[i + 4] = carry', status, ...(trap ? { trap } : {}) }];
  const entry = (extra = {}) => ({ ...m, reason: 'the mutant writes one past the buffer on every call, a deterministic crash', ...extra });
  const t = (name, errs, ok) => { if ((errs.length === 0) !== ok) { console.error(`runerr-gate selftest FAILED: ${name}: ${JSON.stringify(errs)}`); process.exit(1); } };
  t('an exact entry passes', judge([m], [], [entry()]), true);
  t('a missing error plainly killed passes (no flag needed)', judge([], res('KILLED'), [entry()]), true);
  t('a missing error with a test-attributed TRAP passes', judge([], res('TRAP', { test: 'T.testX', message: 'Fatal error: Index out of range' }), [entry()]), true);
  t('a TRAP without a test does not count', judge([], res('TRAP', { message: 'Fatal error' }), [entry()]), false);
  t('a TRAP record with no trap field does not count', judge([], res('TRAP'), [entry()]), false);
  t('the missing one survived fails', judge([], res('SURVIVED'), [entry()]), false);
  t('the missing one is absent fails', judge([], [], [entry()]), false);
  t('another mutant killed does not count', judge([], [{ ...res('KILLED')[0], repl: 'r[i + 6] = carry' }], [entry()]), false);
  t('a RUNERR or TIMEOUT result does not count', judge([], [...res('RUNERR'), ...res('TIMEOUT')], [entry()]), false);
  t('more errors than the multiplicity fails', judge([m, m], res('KILLED'), [entry()]), false);
  t('multiplicity 2: one error plus one killed passes', judge([m], res('KILLED'), [entry({ multiplicity: 2 })]), true);
  t('multiplicity 2: one error alone fails', judge([m], [], [entry({ multiplicity: 2 })]), false);
  t('an unlisted run error fails', judge([m], [], []), false);
  t('a short reason fails', judge([m], [], [entry({ reason: 'crashes' })]), false);
  console.log('runerr-gate selftest ok');
}

if (process.argv[2] === '--selftest') selftest();
else if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  selftest();
  const [reports, resultsDir, ledger, want] = process.argv.slice(2);
  const got = []; let lists = 0;
  walk(reports, /^run-errors-\d+\.json$/, (p) => { lists++; got.push(...JSON.parse(fs.readFileSync(p, 'utf8'))); });
  if (lists !== Number(want)) { console.error(`::error::run-error lists from ${lists}/${want} reports (a missing list is a failure)`); process.exit(1); }
  const results = [];
  if (fs.existsSync(resultsDir)) walk(resultsDir, /^results\.json$/, (p) => results.push(...JSON.parse(fs.readFileSync(p, 'utf8'))));
  const led = JSON.parse(fs.readFileSync(ledger, 'utf8'));
  const errs = judge(got, results, led);
  for (const e of errs) console.error(`::error::${e}`);
  console.log(`${got.length} run error(s) over ${lists} reports, ${led.length} ledger entries, ${errs.length} problem(s)`);
  process.exit(errs.length ? 1 : 0);
}
