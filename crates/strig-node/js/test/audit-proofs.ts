// Merkle proofs and RFC 3161 time stamps verified from JavaScript, on both backends.
// The Merkle vectors are RFC 6962 (the leaves of its reference tests) and the stamp is a response
// recorded from a public TSA; both are pinned in `docs/audit-format.md` and in the Rust tests.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { load } from '../dist/node.js';

let failures = 0;
async function test(name: string, fn: () => unknown) {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    process.exitCode = 1;
    console.log(`not ok - ${name}\n  ${error instanceof Error ? error.stack : error}`);
  }
}

const fixture = (name: string) => readFileSync(new URL(`../../../strig/tests/fixtures/timestamp/${name}`, import.meta.url));

const ROOT_8 = '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328';
const ROOT_3 = 'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77';
const LEAF_5 = '4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658';
const INCLUSION_5_OF_8 = [
  'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
  'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
];
const CONSISTENCY_3_TO_8 = [
  '0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7',
  '07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
];

for (const backend of ['native', 'wasm'] as const) {
  await test(`${backend}: prova de inclusão Merkle (RFC 6962)`, async () => {
    const { verifyMerkleInclusion } = await load({ backend });
    const input = { leaf: LEAF_5, index: 5, size: 8, proof: INCLUSION_5_OF_8, root: ROOT_8 };
    assert.deepEqual(verifyMerkleInclusion(input), { ok: true });
    const wrongIndex = verifyMerkleInclusion({ ...input, index: 4 });
    assert.equal(wrongIndex.ok === false && wrongIndex.code, 'ROOT_MISMATCH');
    const short = verifyMerkleInclusion({ ...input, proof: INCLUSION_5_OF_8.slice(1) });
    assert.equal(short.ok === false && short.code, 'PROOF_LENGTH');
    const outside = verifyMerkleInclusion({ ...input, index: 8 });
    assert.equal(outside.ok === false && outside.code, 'INDEX_OUT_OF_RANGE');
    const flipped = verifyMerkleInclusion({ ...input, root: ROOT_3 });
    assert.equal(flipped.ok === false && flipped.code, 'ROOT_MISMATCH');
  });

  await test(`${backend}: prova de consistência Merkle (RFC 6962)`, async () => {
    const { verifyMerkleConsistency } = await load({ backend });
    const input = { first: 3, second: 8, firstRoot: ROOT_3, secondRoot: ROOT_8, proof: CONSISTENCY_3_TO_8 };
    assert.deepEqual(verifyMerkleConsistency(input), { ok: true });
    const rewritten = verifyMerkleConsistency({ ...input, firstRoot: LEAF_5 });
    assert.equal(rewritten.ok === false && rewritten.code, 'ROOT_MISMATCH');
    const sizes = verifyMerkleConsistency({ ...input, first: 9 });
    assert.equal(sizes.ok === false && sizes.code, 'SIZES');
  });

  await test(`${backend}: entrada malformada de prova é INVALID_INPUT, não resposta`, async () => {
    const { verifyMerkleInclusion } = await load({ backend });
    const base = { index: 0, size: 1, proof: [], root: ROOT_8 };
    assert.throws(() => verifyMerkleInclusion({ ...base, leaf: 'zz' }), { code: 'INVALID_INPUT' });
    assert.throws(() => verifyMerkleInclusion({ ...base }), { code: 'INVALID_INPUT' });
    assert.throws(() => verifyMerkleInclusion({ ...base, leaf: LEAF_5, record: {} }), { code: 'INVALID_INPUT' });
    assert.throws(() => verifyMerkleInclusion({ ...base, record: { not: 'a record' } }), { code: 'INVALID_INPUT' });
  });

  await test(`${backend}: carimbo RFC 3161 gravado verifica sem rede`, async () => {
    const { verifyTimestamp } = await load({ backend });
    const head = createHash('sha256').update(fixture('data.txt')).digest('hex');
    const input = {
      response: fixture('resp.tsr').toString('base64'),
      head,
      roots: fixture('cacert.pem').toString(),
      nonce: '589fa81cde1d083c',
    };
    const stamp = verifyTimestamp(input);
    assert.ok(stamp.ok, JSON.stringify(stamp));
    if (stamp.ok) {
      assert.equal(stamp.genTime, 1_795_868_280);
      assert.equal(stamp.time, '2026-11-28T12:18:00Z');
      assert.equal(stamp.serial, '0ac20a6c');
      assert.equal(stamp.policy, '1.2.3.4.1');
      assert.equal(stamp.imprint, head);
    }
    const other = verifyTimestamp({ ...input, head: '00'.repeat(32) });
    assert.equal(other.ok === false && other.code, 'IMPRINT_MISMATCH');
    const nonce = verifyTimestamp({ ...input, nonce: '01' });
    assert.equal(nonce.ok === false && nonce.code, 'NONCE_MISMATCH');
    const noRoot = verifyTimestamp({ ...input, roots: '' });
    assert.equal(noRoot.ok === false && noRoot.code, 'UNTRUSTED_CHAIN');
    const damaged = Buffer.from(fixture('resp.tsr'));
    damaged[damaged.length - 5] = (damaged[damaged.length - 5] ?? 0) ^ 0xff;
    assert.equal(verifyTimestamp({ ...input, response: damaged.toString('base64') }).ok, false);
    assert.equal(verifyTimestamp({ ...input, response: '' }).ok, false);
    assert.throws(() => verifyTimestamp({ ...input, response: '***' }), { code: 'INVALID_INPUT' });
  });
}

if (failures) console.log(`# audit-proofs: ${failures} falha(s)`);
