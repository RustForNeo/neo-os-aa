import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { MORPHEUS_PUBLIC_REGISTRY } from '../src/config/generatedMorpheusRegistry.js';

// README.md and the docs viewer's copy restate the generated Morpheus registry by
// hand. Keep both equal to it so the prose cannot drift from the gated copy.
const frontendRoot = path.resolve(import.meta.dirname, '..');
const DOCUMENTS = [
  path.join(frontendRoot, '..', 'README.md'),
  path.join(frontendRoot, 'src', 'assets', 'docs', 'repo-readme.md'),
];

const TABLE_ROWS = {
  'AA core': 'aaCore',
  'Morpheus Oracle': 'morpheusOracle',
  'Morpheus DataFeed': 'morpheusDatafeed',
  'Oracle callback consumer': 'oracleCallbackConsumer',
  NeoDIDRegistry: 'morpheusNeoDid',
  'AA Web3AuthVerifier': 'aaWeb3AuthVerifier',
  'SocialRecoveryVerifier v2': 'aaSocialRecoveryVerifier',
};

const HASH = /`(0x[0-9a-fA-F]{40})`/;

function anchorSection(markdown, file) {
  const start = markdown.indexOf('## Canonical Morpheus Network Anchors');
  assert.notEqual(start, -1, `${file} has no Canonical Morpheus Network Anchors section`);
  const rest = markdown.slice(start + 1);
  const end = rest.search(/\n#/);
  return end === -1 ? rest : rest.slice(0, end);
}

function literal(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function relative(file) {
  return path.relative(path.join(frontendRoot, '..'), file);
}

for (const file of DOCUMENTS) {
  const markdown = fs.readFileSync(file, 'utf8');
  const name = relative(file);

  test(`${name} anchor table matches the generated Morpheus registry`, () => {
    const rows = anchorSection(markdown, name)
      .split('\n')
      .filter((line) => line.startsWith('| ') && !line.startsWith('| Item') && !line.startsWith('| ---'))
      .map((line) => line.split('|').slice(1, -1).map((cell) => cell.trim()));
    const checked = new Set();
    for (const [label, mainnetCell, testnetCell] of rows) {
      const key = TABLE_ROWS[label];
      if (!key) {
        assert.ok(!HASH.test(mainnetCell) && !HASH.test(testnetCell), `${name}: add the row "${label}" to TABLE_ROWS`);
        continue;
      }
      checked.add(label);
      for (const [network, cell] of [['mainnet', mainnetCell], ['testnet', testnetCell]]) {
        const canonical = MORPHEUS_PUBLIC_REGISTRY[network].contracts[key];
        const stated = cell.match(HASH)?.[1];
        if (canonical) {
          assert.equal(stated?.toLowerCase(), canonical.toLowerCase(), `${name}: ${label} (${network})`);
        } else {
          assert.equal(stated, undefined, `${name}: ${label} (${network}) is unpublished in the registry`);
        }
      }
    }
    assert.deepEqual([...checked].sort(), Object.keys(TABLE_ROWS).sort(), `${name}: anchor rows`);
  });

  test(`${name} domain rules and status notes match the generated Morpheus registry`, () => {
    const { mainnet, testnet } = MORPHEUS_PUBLIC_REGISTRY;
    const section = anchorSection(markdown, name);
    assert.match(section, new RegExp(`- mainnet AA domain: \`${literal(mainnet.domains.aa)}\``));
    assert.match(section, new RegExp(`- mainnet AA additional alias: \`${literal(mainnet.domains.aaAlias)}\``));
    assert.match(section, new RegExp(`- mainnet NeoDID domain: \`${literal(mainnet.domains.neodid)}\``));
    assert.match(section, /- testnet currently has no shared AA \/ NeoDID NNS aliases/);
    assert.deepEqual([testnet.domains.aa, testnet.domains.aaAlias, testnet.domains.neodid], ['', '', '']);

    const mainnetNote = markdown.match(
      /canonical mainnet AA anchor now points to the clean deploy `(0x[0-9a-f]{40})` and resolves from `([^`]+)` plus `([^`]+)`/
    );
    assert.ok(mainnetNote, `${name}: mainnet status note`);
    assert.deepEqual(mainnetNote.slice(1), [mainnet.contracts.aaCore, mainnet.domains.aa, mainnet.domains.aaAlias]);

    const testnetNote = markdown.match(
      /canonical shared testnet AA anchor now points to the clean deployment `(0x[0-9a-f]{40})`, with shared `Web3AuthVerifier` `(0x[0-9a-f]{40})`/
    );
    assert.ok(testnetNote, `${name}: testnet status note`);
    assert.deepEqual(testnetNote.slice(1), [testnet.contracts.aaCore, testnet.contracts.aaWeb3AuthVerifier]);
  });
}
