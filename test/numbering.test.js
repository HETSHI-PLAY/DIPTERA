/* Unit test untuk numbering.js — jalankan dengan: node test/numbering.test.js */
'use strict';

const assert = require('node:assert/strict');
const N = require('../src/services/numbering.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log('  ✓ ' + name);
  } catch (err) {
    failed++;
    console.log('  ✕ ' + name);
    console.log('    ' + String(err.message).split('\n').join('\n    '));
  }
}

console.log('numbering.js');

test('angka polos dimajukan', () => {
  assert.equal(N.nextValue('10010'), '10011');
  assert.equal(N.nextValue('9'), '10');
  assert.equal(N.nextValue(' 10010 '), '10011');
});

test('prefiks # dan sufiks terjaga', () => {
  assert.equal(N.nextValue('#1001'), '#1002');
  assert.equal(N.nextValue('#999'), '#1000');
  assert.equal(N.nextValue('#123'), '#124');
});

test('lebar nol dipertahankan', () => {
  assert.equal(N.nextValue('007'), '008');
  assert.equal(N.nextValue('#0007'), '#0008');
  assert.equal(N.nextValue('0999'), '1000');
});

test('hanya angka terakhir yang dimajukan', () => {
  assert.equal(N.nextValue('ASOC-2026-30073'), 'ASOC-2026-30074');
  assert.equal(N.nextValue('CASE/1001/2'), 'CASE/1001/3');
});

test('nilai tanpa angka -> null', () => {
  assert.equal(N.nextValue(''), null);
  assert.equal(N.nextValue('   '), null);
  assert.equal(N.nextValue('tanpa angka'), null);
  assert.equal(N.nextValue(null), null);
  assert.equal(N.nextValue(undefined), null);
});

test('lastNumber mengembalikan grup terakhir', () => {
  assert.deepEqual(N.lastNumber('ASOC-2026-30073'), { index: 10, text: '30073', value: 30073, width: 5 });
  assert.deepEqual(N.lastNumber('#1001'), { index: 1, text: '1001', value: 1001, width: 4 });
  assert.equal(N.lastNumber('abc'), null);
});

test('berulang kali naik satu-satu', () => {
  let v = '1001';
  const seq = [];
  for (let i = 0; i < 5; i++) {
    v = N.nextValue(v);
    seq.push(v);
  }
  assert.deepEqual(seq, ['1002', '1003', '1004', '1005', '1006']);
});

console.log('\n' + passed + ' lulus, ' + failed + ' gagal');
process.exit(failed ? 1 : 0);
