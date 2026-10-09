// Guards the AA documentation against the drift CU-163 measured: documented entrypoints,
// paymaster ABI names, SDK method names, deployment hashes, the VULN-001 state and cited
// receipts. The oracles are machine-readable and live in code or in committed artifacts:
//
//   contracts/build/*.manifest.json          the ABI actually deployed (SHA-256 pinned by
//                                            tests/localchain/expected-deployed.json)
//   sdk/js/src/**                            the SDK that exists
//   frontend/src/config/generatedMorpheusRegistry.js
//                                            the canonical Morpheus anchors, generated from
//                                            neo-os-services (README: it wins on any conflict)
//   tests/localchain/expected-source.json    the pinned deployed NEF path
//   the filesystem                           cited receipts
//
// A rule must be able to fail, so §7 of DS-CU-163-20261009.md pairs every rule with a document
// mutant and, where the rule reads an artifact, an oracle mutant.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MORPHEUS_PUBLIC_REGISTRY } from '../src/config/generatedMorpheusRegistry.js';
// The native ABI 2 profile is a separate runtime with its own documents (DS-CU-163 section 2.2
// excludes it from the current-runtime documents), and NativeSmartAccountClient declares the exact
// method set it validates a deployment against. A native callable is live when that artefact names
// it, the same way a deployed manifest makes an N3 callable live (DS-CU-202 section 3).
import { NATIVE_REQUIRED_ABI } from '../../shared/nativeSmartAccountClient.mjs';

const frontendRoot = fileURLToPath(new URL('..', import.meta.url));
const repoRoot = path.resolve(frontendRoot, '..');
const read = (relative) => fs.readFileSync(path.join(repoRoot, relative), 'utf8');
const exists = (relative) => fs.existsSync(path.join(repoRoot, relative));

// Documents whose claims must hold for the runtime that ships today. DS-CU-163-20261009.md
// section 5 lists them and records why the rest of the V2-era documents are debt instead.
const CURRENT_DOCS = [
  'README.md',
  'docs/PLUGIN_MATRIX.md',
  'docs/QUICK_REFERENCE.md',
  'docs/architecture.md',
  'frontend/src/assets/docs/repo-readme.md',
  'frontend/src/assets/docs/sdk-usage.md',
  'frontend/src/assets/docs/evm-integration.md',
  'frontend/src/assets/docs/mixed-multisig.md',
  'frontend/src/assets/docs/architecture.md',
  'docs/PLUGIN_DEVELOPER_GUIDE.md',
];

// A snapshot audit: its method names are the ones that existed when it was written, so it is not
// held to the current ABI, but its VULN-001 status must still agree with the deployed artifact and
// its cited receipts must exist. DS-CU-163 section 4.3 V3.
const AUDIT_DOCS = ['frontend/src/assets/docs/SECURITY_AUDIT.md'];

// The native ABI 2 profile is a separate runtime with its own documents (DS-CU-163 section 2.2),
// and NativeSmartAccountClient declares the exact method set it validates a deployment against.
// Only these documents are read against that artefact; a name that merely coincides with a native
// method (callVerifierChild is also defined in contracts/UnifiedSmartWallet.VerifierChildren.cs and
// absent from the deployed manifest) is still judged by the deployed ABI everywhere else.
const NATIVE_PROFILE_DOCS = ['docs/NATIVE_SDK.md', 'docs/NATIVE_ACCOUNT_WORKSPACE.md'];
const nativeAbiNames = new Set(Object.keys(NATIVE_REQUIRED_ABI));
const NO_NAMES = new Set();

// Documents that still describe the removed V2 runtime. The list is a ratchet: it records the
// exact names each document may still mention and fails when one grows (new drift) or shrinks
// (the document was corrected and the entry must be dropped). DS-CU-163 section 10 recommends
// the follow-up row that removes the remaining entries.
const V2_DEBT = {
  'docs/DEPENDENCY-CONVERGENCE-20261008.md': ['entrypoint:getAuthTokenInfo'],
  'docs/ETHEREUM_AA_COMPARISON.md': ['case:FinalizeEscape', 'case:InitiateEscape', 'case:RegisterAccount', 'case:ValidatePaymasterOp', 'entrypoint:validateUserOp'],
  'docs/MULTISIG_CHILD_CONFIGURATION.md': ['entrypoint:callVerifierChild', 'entrypoint:getChildVerifierConfig'],
  'docs/MULTISIG_SDK.md': ['entrypoint:buildBundle', 'entrypoint:buildChildConfiguration', 'entrypoint:buildChildTypedData', 'entrypoint:callHash', 'entrypoint:callVerifierChild'],
  'docs/PROTOCOL_COMPLETENESS_AUDIT.md': ['case:CanConfigureHook', 'case:CanConfigureVerifier', 'case:CancelHookUpdate', 'case:CancelMarketEscrow', 'case:CancelVerifierUpdate', 'case:ConfirmHookUpdate', 'case:ConfirmVerifierUpdate', 'case:ExecuteUserOp', 'case:FinalizeEscape', 'case:IsMarketEscrowActive', 'case:RegisterAccount', 'case:SettleMarketEscrow', 'case:UpdateHook', 'case:UpdateVerifier', 'entrypoint:validatePaymasterUserOp'],
  'docs/SECURITY_AUDIT.md': ['case:CanExecuteHook', 'case:SettleMarketEscrow', 'case:ValidateSignature', 'entrypoint:IsAnyExecutionActive', 'entrypoint:IsDomeOracleUnlocked'],
  'docs/SECURITY_AUDIT_RESULTS.md': ['case:CallHook', 'case:CallVerifier', 'case:CanConfigureHook', 'case:CanConfigureVerifier', 'case:ConfirmHookUpdate', 'case:ConfirmVerifierUpdate', 'case:CreateListing', 'case:ExecuteUserOp', 'case:FinalizeEscape', 'case:InitiateEscape', 'case:RegisterAccount', 'case:RotateAdmin', 'case:SetDailyLimit', 'case:SetHooks', 'case:SetSessionKey', 'case:SettleListing', 'case:SettleMarketEscrow', 'case:UpdateHook', 'case:UpdateListingPrice', 'case:UpdateVerifier', 'case:ValidateSignature', 'entrypoint:IsAnyExecutionActive'],
  'docs/TRANSACTION_FLOW.md': ['entrypoint:ExecuteUnifiedByAddress'],
  'docs/USER_GUIDE.md': ['legacy:getAccountsByAdmin', 'legacy:getAccountsByManager', 'sdk:createAccountBatchPayload'],
  'frontend/src/assets/docs/SECURITY_AUDIT.md': ['case:CanExecuteHook', 'case:SettleMarketEscrow', 'case:ValidateSignature', 'entrypoint:IsAnyExecutionActive', 'entrypoint:IsDomeOracleUnlocked'],
};

// Framework and service calls that share a name with a contract method but are not one.
// ContractManagement is the Neo native contract: contracts/UnifiedSmartWallet.Accounts.cs:404 calls
// ContractManagement.GetContract and tests/AbstractAccount.Contracts.Tests/*.cs invoke the native
// "getContract" by string, so a document that reads a NEF back that way names no AA entrypoint.
const FRAMEWORK_RECEIVERS = new Set(['Runtime', 'Contract', 'ContractManagement', 'System', 'CryptoLib', 'Storage', 'Helper', 'ExecutionEngine', 'Neo']);
// Inline code that looks like an entrypoint but is a parameter, a field or a service name.
const NON_CALLABLES = new Set(['create_aa_draft', 'claimCommitment', 'callData', 'signMessage', 'getPending']);

const ENTRYPOINT = /^(?:execute|register|preview|initiate|finalize|settle|update|cancel|confirm|propose|compute|get|set|is|has|can|withdraw|revoke|rotate|claim|deposit|call|lock|unlock|create|build|derive|validate|query|prepare|sign|broadcast|discover)[A-Z][A-Za-z0-9]*$/;
// A line that marks a name as gone. The repository's translation copies state removal in Chinese,
// so the marker vocabulary is not English-only; "旧版" (legacy) deliberately does NOT mark a
// removal, because "legacy X is compatibility-only" was itself the false claim (DS-CU-163 B2).
const REMOVED = /remov|superseded|no longer|not part|does not exist|never existed|absent|retired|deleted|dropped|gone|were never|移除|删除|弃用|废弃|不再/i;

const deployedAbi = new Map(); // exact ABI name -> the manifest that carries it
for (const file of fs.readdirSync(path.join(repoRoot, 'contracts/build'))) {
  if (!file.endsWith('.manifest.json')) continue;
  const manifest = JSON.parse(read(path.join('contracts/build', file)));
  for (const method of manifest.abi.methods) deployedAbi.set(method.name, file);
  for (const event of manifest.abi.events ?? []) deployedAbi.set(event.name, file);
}
const deployedAbiLower = new Map([...deployedAbi.keys()].map((name) => [name.toLowerCase(), name]));

// Every name the repository defines or calls somewhere in code. A documented name that is absent
// from both this set and the deployed ABI is dead unless the sentence marks it removed. Strings and
// comments do not count: `'executeUnifiedByAddress'` in an allowlist is a string, not a definition.
const definedNames = new Set(deployedAbi.keys());
const tracked = [];
const SKIP_DIRS = new Set(['node_modules', '.git', 'obj', 'bin', 'dist', 'coverage', 'test-results', '.next', '.codegraph', '.turbo', '.vercel', 'tmp']);
(function walk(dir) {
  for (const entry of fs.readdirSync(path.join(repoRoot, dir), { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name) || (entry.name.startsWith('.') && entry.name !== '.')) continue;
    const relative = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(relative);
    else tracked.push(relative);
  }
})('.');
for (const file of tracked) {
  if (!/\.(cs|js|mjs|ts|py|sql|json)$/.test(file)) continue;
  // Test drivers are not the product surface, and docs are prose about it.
  if (file.startsWith('docs/') || file.startsWith('frontend/tests/') || file.startsWith('tests/') || file.startsWith('sdk/js/tests/')) continue;
  const text = read(file);
  // A call is a call whether or not it is optional-chained: frontend/src/features/native/
  // nativeWorkspace.js calls `provider.getNetworks?.()`.
  for (const match of text.matchAll(/([A-Za-z_]\w*)\s*\??\.?\s*\(/g)) definedNames.add(match[1]);
  for (const match of text.matchAll(/DisplayName\("([^"]+)"\)/g)) definedNames.add(match[1]);
  // A contract may only call what its permissions name, and the pinned native authority calls the
  // service by string (contracts/native/NativeAuthority.cs). Both spellings are live names, and the
  // scanner above cannot see them because the method is a string literal, not a call.
  for (const line of text.split('\n')) {
    if (!/ContractPermission|Contract\.Call/.test(line)) continue;
    for (const match of line.matchAll(/"([A-Za-z_]\w*)"/g)) definedNames.add(match[1]);
  }
}

// The SDK surface: class methods plus the methods that unconditionally report a V3 removal. The
// native client lives in shared/nativeSmartAccountClient.mjs and is re-exported by sdk/js/src.
const sdkMethods = new Set();
const legacySdkMethods = new Set();
for (const file of tracked) {
  if (!/\.(js|mjs)$/.test(file)) continue;
  if (!file.startsWith('sdk/js/src/') && !file.startsWith('shared/')) continue;
  const text = read(file);
  for (const match of text.matchAll(/^\s*(?:async\s+)?(?:static\s+)?([A-Za-z_]\w*)\s*\([^)]*\)\s*\{/gm)) sdkMethods.add(match[1]);
  for (const match of text.matchAll(/^\s*(?:async\s+)?([A-Za-z_]\w*)\s*\([^)]*\)\s*\{([\s\S]*?)\n  \}/gm)) {
    if (/LEGACY_V3_REMOVED/.test(match[2])) legacySdkMethods.add(match[1]);
  }
}

// The deployed NEF: the gas-bounded syscall VULN-001 is about. The token is read from the
// pinned artifact, never from a document.
const GAS_BOUNDED_SYSCALL = 'System.Contract.CallWithGasLimit';
const NEF_SYSCALL_OPCODE = 0x41;
const OPERAND_SIZE = {
  0x00: 1, 0x01: 2, 0x02: 4, 0x03: 8, 0x04: 16, 0x05: 32, 0x0a: 4,
  0x22: 1, 0x23: 4, 0x24: 1, 0x25: 4, 0x26: 1, 0x27: 4, 0x28: 1, 0x29: 4,
  0x2a: 1, 0x2b: 4, 0x2c: 1, 0x2d: 4, 0x2e: 1, 0x2f: 4, 0x30: 1, 0x31: 4,
  0x32: 1, 0x33: 4, 0x34: 1, 0x35: 4, 0x37: 2, 0x3b: 2, 0x3c: 8, 0x3e: 4,
  0x41: 4, 0x56: 1, 0x57: 2, 0x5f: 1, 0x67: 1, 0x6f: 1, 0x77: 1, 0x7f: 1,
  0x87: 1, 0xc4: 1, 0xd9: 1, 0xdb: 1,
};
const PUSHDATA_PREFIX = { 0x0c: 1, 0x0d: 2, 0x0e: 4 };
const GAS_BOUNDED_INTEROP = 1371299780;

function readVarint(bytes, offset) {
  const first = bytes[offset];
  if (first < 0xfd) return [first, offset + 1];
  const width = { 0xfd: 2, 0xfe: 4, 0xff: 8 }[first];
  return [Number(bytes.readUIntLE(offset + 1, width)), offset + 1 + width];
}

function readVarstring(bytes, offset) {
  const [length, next] = readVarint(bytes, offset);
  return [bytes.subarray(next, next + length), next + length];
}

// Walk the NEF header the way NefFile does and return the contract script.
function nefScript(file) {
  const bytes = fs.readFileSync(path.join(repoRoot, file));
  assert.equal(bytes.subarray(0, 4).toString('ascii'), 'NEF3', `${file} is not a NEF3 artifact`);
  let offset = 4 + 64; // magic + compiler
  [, offset] = readVarstring(bytes, offset); // source
  assert.equal(bytes[offset], 0, `${file}: reserved byte after the source is not zero`);
  offset += 1;
  const [tokenCount, afterCount] = readVarint(bytes, offset);
  offset = afterCount;
  for (let i = 0; i < tokenCount; i += 1) {
    offset += 20; // token hash
    [, offset] = readVarstring(bytes, offset); // method
    offset += 4; // parameters + return value + call flags
  }
  assert.equal(bytes[offset], 0, `${file}: reserved bytes before the script are not zero`);
  assert.equal(bytes[offset + 1], 0, `${file}: reserved bytes before the script are not zero`);
  offset += 2;
  const [scriptLength, afterLength] = readVarint(bytes, offset);
  return bytes.subarray(afterLength, afterLength + scriptLength);
}

function gasBoundedCallSites(file) {
  const script = nefScript(file);
  const sites = [];
  let i = 0;
  while (i < script.length) {
    const opcode = script[i];
    if (opcode === NEF_SYSCALL_OPCODE) {
      const token = script.readUInt32LE(i + 1);
      if (token === GAS_BOUNDED_INTEROP) sites.push(i);
      i += 1 + OPERAND_SIZE[0x41];
      continue;
    }
    if (PUSHDATA_PREFIX[opcode] !== undefined) {
      const lengthSize = PUSHDATA_PREFIX[opcode];
      const length = lengthSize === 1 ? script[i + 1] : lengthSize === 2 ? script.readUInt16LE(i + 1) : script.readUInt32LE(i + 1);
      i += 1 + lengthSize + length;
      continue;
    }
    const size = OPERAND_SIZE[opcode];
    i += size === undefined ? 1 : 1 + size;
  }
  return sites;
}

const deployedCorePath = JSON.parse(read('tests/localchain/expected-source.json')).deployedCore.path;
const gasBoundedSites = gasBoundedCallSites(deployedCorePath);
const canonicalHashes = new Set();
(function collect(value) {
  if (typeof value === 'string') canonicalHashes.add(value.toLowerCase());
  else if (value && typeof value === 'object') for (const child of Object.values(value)) collect(child);
})(MORPHEUS_PUBLIC_REGISTRY);

function codeSpans(line) {
  const spans = [];
  for (const match of line.matchAll(/`([^`]+)`/g)) spans.push(match[1].trim());
  return spans;
}

function callableNames(line) {
  const names = [];
  for (const span of codeSpans(line)) {
    const withoutCall = span.replace(/\(.*$/, '');
    for (const segment of withoutCall.split(/[\s,;/]+/)) {
      const receiver = segment.includes('.') ? segment.slice(0, segment.lastIndexOf('.')) : '';
      const last = segment.split('.').pop();
      if (!last || !/^[A-Za-z_]\w*$/.test(last)) continue;
      const receivers = receiver.split('.');
      if (FRAMEWORK_RECEIVERS.has(last) || receivers.some((part) => FRAMEWORK_RECEIVERS.has(part))) continue;
      if (NON_CALLABLES.has(last)) continue;
      if (!ENTRYPOINT.test(last[0].toLowerCase() + last.slice(1))) continue;
      names.push({ name: last, called: span.includes('('), receiver });
    }
  }
  return names;
}

// A section that declares itself historical is allowed to name the runtime it describes.
function historicalSections(lines) {
  const flags = new Array(lines.length).fill(false);
  let historical = false;
  lines.forEach((line, index) => {
    if (/^#{2,4}\s/.test(line)) historical = /historical|archived|removed|V1\/V2|pre-V3/i.test(line);
    flags[index] = historical;
  });
  return flags;
}

function failures() {
  const problems = [];
  for (const file of [...CURRENT_DOCS, ...AUDIT_DOCS]) {
    assert.ok(exists(file), `guarded document ${file} does not exist`);
    const nameRules = CURRENT_DOCS.includes(file);
    const lines = read(file).split('\n');
    const historical = historicalSections(lines);
    let fence = false;
    lines.forEach((line, index) => {
      const where = `${file}:${index + 1}`;
      const markedRemoved = REMOVED.test(line) || historical[index];
      if (/^\s*```/.test(line)) { fence = !fence; return; }
      if (nameRules) for (const { name } of callableNames(line)) {
        if (deployedAbi.has(name)) continue;
        if (deployedAbiLower.has(name.toLowerCase())) {
          problems.push(`${where}: ${name} is not a deployed ABI name; the artifact spells it ${deployedAbiLower.get(name.toLowerCase())}`);
          continue;
        }
        if (definedNames.has(name)) continue;
        if (markedRemoved) continue;
        problems.push(`${where}: ${name} is not defined in any contract, manifest or SDK source and the line does not mark it removed`);
      }
      if (nameRules && fence && !markedRemoved) for (const match of line.matchAll(/\b0x[0-9a-fA-F]{40}\b/g)) {
        if (canonicalHashes.has(match[0].toLowerCase())) continue;
        if (!/current|canonical|verified hardened|masterHash|AA_RELAY_ALLOWED_HASH/i.test(line)) continue;
        problems.push(`${where}: ${match[0]} is presented as the current deployment but is not in generatedMorpheusRegistry.js`);
      }
      if (nameRules && !markedRemoved) for (const match of line.matchAll(/\b(?:aaClient|client|sdk)\.([A-Za-z_]\w*)\s*\(/g)) {
        const name = match[1];
        if (legacySdkMethods.has(name)) problems.push(`${where}: ${name} always throws LEGACY_V3_REMOVED in the SDK and must not be documented as usable`);
        else if (!sdkMethods.has(name)) problems.push(`${where}: ${name} is not an SDK method`);
      }
      for (const match of line.matchAll(/`(docs\/[\w./-]+\.(?:json|md))`/g)) {
        if (!exists(match[1])) problems.push(`${where}: cited receipt ${match[1]} does not exist`);
      }
      if (/VULN-001/.test(line) && /fix|clos|resolv|mitigat|eliminat/i.test(line) && !/private|only|not\b|pending|open|historical/i.test(line)) {
        if (gasBoundedSites.length === 0) {
          problems.push(`${where}: ${file} claims VULN-001 closed, but ${deployedCorePath} carries no ${GAS_BOUNDED_SYSCALL} call site`);
        }
      }
    });
    if (nameRules) {
      // Hashes in prose are checked per paragraph, not per line: the prose wraps, and a stale
      // anchor on the second line of a sentence must not escape the rule. Fenced examples keep the
      // line check above, because a code block is where a placeholder hash lives.
      const prose = read(file).replace(/^\s*```[\s\S]*?^\s*```/gm, '');
      for (const paragraph of prose.split(/\n\s*\n/)) {
        const flat = paragraph.replace(/\s+/g, ' ');
        if (!/current|canonical|verified hardened|masterHash|AA_RELAY_ALLOWED_HASH/i.test(flat)) continue;
        if (REMOVED.test(flat)) continue;
        for (const match of flat.matchAll(/\b0x[0-9a-fA-F]{40}\b/g)) {
          if (canonicalHashes.has(match[0].toLowerCase())) continue;
          problems.push(`${file}: ${match[0]} is presented as the current deployment but is not in generatedMorpheusRegistry.js (paragraph: ${flat.slice(0, 90)}…)`);
        }
      }
      // A section that reports the matrix as verified or passed must say which target the run used.
      // The script that produced the record targets MockTransferTarget, so the disclosure is not
      // prose decoration: without it a reader takes an authorization result for a value transfer.
      let section = [];
      const flush = (heading) => {
        const text = section.join('\n');
        if (/verified on-chain|passed on testnet/i.test(text) && !/MockTransferTarget|mock (contract|target)/i.test(text)) {
          problems.push(`${file}: the section "${heading}" reports the plugin matrix as verified on chain without disclosing the MockTransferTarget target the matrix script uses`);
        }
        section = [];
      };
      let heading = 'preamble';
      for (const line of read(file).split('\n')) {
        if (/^#{1,6}\s/.test(line)) { flush(heading); heading = line.trim(); }
        section.push(line);
      }
      flush(heading);
    }
  }
  return problems;
}

test('CU-163: the current-runtime documents state only what the code and the deployed artifacts decide', () => {
  const problems = failures();
  assert.deepEqual(problems, [], `documentation drift:\n${problems.join('\n')}`);
});

// The ledger, not a document's prose, is the current VULN-001 state. While the deployed artifact
// carries no bounded call site the ledger must say the public state is open; if the artifact ever
// gains the bounded call, this fails until the ledger is updated too.
test('CU-163: the VULN-001 ledger agrees with the deployed artifact', () => {
  const row = read('docs/SECURITY_MODEL.md').split('\n').find((line) => /\*\*VULN-001\*\*/.test(line));
  assert.ok(row, 'docs/SECURITY_MODEL.md has no VULN-001 row');
  if (gasBoundedSites.length === 0) {
    assert.match(row, /open|not\b|pending/i,
      `the deployed core has no ${GAS_BOUNDED_SYSCALL} call site, so the ledger must not close VULN-001 for the public build`);
  }
});

// Presentation rule for snapshot audits: a VULN-00N item must sit under a heading that calls the
// snapshot historical. This is weaker than the artifact checks above and is stated as such — it
// cannot prove an item is right, only that a reader is not shown a pre-remediation list as current.
// The rendered copy must also stay equal to the repository copy, which is the copy the ledger rule
// above is about.
test('CU-163: the rendered audit presents its findings as the historical snapshot', () => {
  for (const file of AUDIT_DOCS) {
    const lines = read(file).split('\n');
    let heading = '';
    lines.forEach((line, index) => {
      if (/^#{1,4}\s/.test(line)) heading = line;
      if (!/VULN-00\d/.test(line)) return;
      const marked = /historical|archived|retained for audit/i.test(line) || /historical|archived|retained for audit/i.test(heading);
      assert.ok(marked, `${file}:${index + 1}: a VULN-00N item is presented outside a historical section`);
    });
  }
  assert.equal(read('frontend/src/assets/docs/SECURITY_AUDIT.md'), read('docs/SECURITY_AUDIT.md'),
    'the rendered security audit has drifted from docs/SECURITY_AUDIT.md');
});

// The ledger is the only place that numbers an issue VULN-00N. A second document reusing an id
// makes a reviewer read two different issues under one name (DS-CU-163 section 4.3 V4).
test('CU-163: only the ledger numbers issues VULN-00N', () => {
  const markdown = tracked.filter((file) => file.endsWith('.md')
    && !file.startsWith('docs/proposals/') && !file.startsWith('docs/reports/') && !file.startsWith('docs/plans/'));
  const collisions = [];
  for (const file of markdown) {
    read(file).split('\n').forEach((line, index) => {
      if (/^#{1,6}\s*VULN-00\d/.test(line)) collisions.push(`${file}:${index + 1}: ${line.trim()}`);
    });
  }
  assert.deepEqual(collisions, [], `a document reuses a ledger identifier as a heading:\n${collisions.join('\n')}`);
});

// The closure claim is checked against the artifact for every document, not only the guarded ones:
// while the deployed core carries no bounded call site, no document may say the public build is
// fixed. A document may say the private artifact is closed when it says so in those words.
test('CU-163: no document closes VULN-001 for the public build while the deployed core has no bounded call', () => {
  if (gasBoundedSites.length > 0) return;
  const markdown = tracked.filter((file) => file.endsWith('.md')
    && !file.startsWith('docs/proposals/') && !file.startsWith('docs/reports/') && !file.startsWith('docs/plans/'));
  const claims = [];
  for (const file of markdown) {
    // A paragraph is the unit: the prose wraps, so the qualifier can sit on the next line.
    const paragraphs = read(file).split(/\n\s*\n/);
    for (const paragraph of paragraphs) {
      const flat = paragraph.replace(/\s+/g, ' ');
      if (!/VULN-001/.test(flat) || !/fix|clos|resolv|mitigat|eliminat/i.test(flat)) continue;
      if (/private|only|not\b|pending|open|historical/i.test(flat)) continue;
      claims.push(`${file}: ${flat.slice(0, 140)}`);
    }
  }
  assert.deepEqual(claims, [], `a document claims VULN-001 closed for the public build while ${deployedCorePath} carries no ${GAS_BOUNDED_SYSCALL} call site:\n${claims.join('\n')}`);
});

test('CU-163: the V2-era documents do not grow new dead references (ratchet)', () => {
  const patterns = {
    entrypoint: (line, file) => (REMOVED.test(line) ? [] : callableNames(line)
      .filter(({ name }) => !(NATIVE_PROFILE_DOCS.includes(file) ? nativeAbiNames : NO_NAMES).has(name))
      .filter(({ name }) => !deployedAbi.has(name) && !definedNames.has(name) && !deployedAbiLower.has(name.toLowerCase()))
      .map(({ name }) => `entrypoint:${name}`)),
    case: (line) => callableNames(line).filter(({ name }) => !deployedAbi.has(name) && deployedAbiLower.has(name.toLowerCase())).map(({ name }) => `case:${name}`),
    sdk: (line) => [...line.matchAll(/\b(?:aaClient|client|sdk)\.([A-Za-z_]\w*)\s*\(/g)].flatMap((match) => legacySdkMethods.has(match[1]) ? [`legacy:${match[1]}`] : sdkMethods.has(match[1]) ? [] : [`sdk:${match[1]}`]),
  };
  const found = {};
  const files = tracked.filter((file) => file.endsWith('.md')
    && !file.startsWith('docs/proposals/') && !file.startsWith('docs/reports/') && !file.startsWith('docs/plans/')
    && !CURRENT_DOCS.includes(file));
  for (const file of files) {
    const names = new Set();
    for (const line of read(file).split('\n')) {
      for (const build of Object.values(patterns)) for (const name of build(line, file)) names.add(name);
    }
    if (names.size) found[file] = [...names].sort();
  }
  if (process.env.DOCS_TRUTH_REPORT) {
    console.log(JSON.stringify(found, null, 2));
    return;
  }
  assert.deepEqual(found, V2_DEBT, 'the V2-era debt list changed: a document drifted, or a corrected document must be removed from the ratchet');
});
