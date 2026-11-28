#!/usr/bin/env node
// Joins the oracle shares of N parallel oracle jobs (mutate.mjs run ... --oracle-out --oracle-part=K/N) into the one oracle.json a slice reads with --oracle-in.
//   node oracle-merge.mjs <dir with one sub-directory per share, each holding oracle.json> <out oracle.json>
// Fails unless every share is there exactly once (K = 0..N-1 of one N), all were verified on the same tree, each verified exactly the groups it was assigned,
// and together they hold every group (the `all` count each share records). A slice never runs on a partial oracle: it would verify the missing groups itself
// (slowly) or, worse, judge against a share of another tree.
import fs from 'node:fs';
import path from 'node:path';

const [dir, out] = process.argv.slice(2);
if (!dir || !out) { console.error('usage: oracle-merge.mjs <shares dir> <out oracle.json>'); process.exit(2); }
const shares = fs.readdirSync(dir).map((d) => path.join(dir, d, 'oracle.json')).filter((f) => fs.existsSync(f)).map((f) => ({ f, o: JSON.parse(fs.readFileSync(f, 'utf8')) }));
const fail = (m) => { console.error(`::error::oracle-merge: ${m}`); process.exit(1); };
if (!shares.length) fail(`no oracle share under ${dir}`);
const parts = shares.map(({ f, o }) => { const m = /^(\d+)\/(\d+)$/.exec(String(o.part)); if (!m) fail(`${f}: part ${o.part} is not K/N`); return { f, o, k: +m[1], n: +m[2] }; });
const n = parts[0].n, tree = parts[0].o.tree, all = parts[0].o.all;
for (const p of parts) {
  if (p.n !== n) fail(`${p.f}: part ${p.o.part}, others are of ${n}`);
  if (p.o.tree !== tree) fail(`${p.f}: tree ${String(p.o.tree).slice(0, 12)}, others ${String(tree).slice(0, 12)}`);
  if (p.o.all !== all) fail(`${p.f}: ${p.o.all} groups in all, others ${all}`);
  const got = Object.keys(p.o.groups).sort(), want = [...p.o.assigned].sort();
  if (JSON.stringify(got) !== JSON.stringify(want)) fail(`${p.f}: verified ${got.length} group(s), was assigned ${want.length}`);
}
const ks = parts.map((p) => p.k).sort((a, b) => a - b);
if (JSON.stringify(ks) !== JSON.stringify([...Array(n).keys()])) fail(`shares ${ks.join(',')} of ${n}: want each of 0..${n - 1} once`);
const groups = {};
for (const p of parts) for (const [g, v] of Object.entries(p.o.groups)) { if (g in groups) fail(`group ${g} in two shares`); groups[g] = v; }
if (Object.keys(groups).length !== all) fail(`${Object.keys(groups).length} groups joined, the plan has ${all}`);
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify({ tree, groups }, null, 1));
console.log(`oracle: ${all} group(s) from ${n} share(s) on tree ${String(tree).slice(0, 12)}`);
