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
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
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

// Documents that still name something the deployed runtime does not carry. The list is a ratchet: it
// records the exact names each document may still mention and fails when one grows (new drift) or
// shrinks (the document was corrected and the entry must be dropped). DS-CU-202 worked the list down
// from 31 files / 109 names to the entries below; every remaining entry carries a reason it must stay
// (row CU-202 acceptance), and an entry that also carries a `marker` is only accepted while the
// document itself still says so - the marker is a scope declaration, not a behaviour oracle.
const V2_DEBT = {
  'docs/DEPENDENCY-CONVERGENCE-20261008.md': {
    names: ['entrypoint:getAuthTokenInfo'],
    reason: 'The name is the token API of the Web3Auth v11 SDK upgrade this record rejects, not a Neo contract method; the document is a package decision record, and no deployed manifest carries it.',
  },
  'docs/ETHEREUM_AA_COMPARISON.md': {
    names: ['entrypoint:validateUserOp'],
    reason: 'The name is the Ethereum ERC-4337 validator entry point on the Ethereum side of an explicit mapping (IVerifier.validateSignature is compared with IValidator.validateUserOp), not a Neo entrypoint.',
  },
  'docs/SECURITY_AUDIT.md': {
    names: ['case:CanExecuteHook', 'case:SettleMarketEscrow', 'case:ValidateSignature', 'entrypoint:IsAnyExecutionActive', 'entrypoint:IsDomeOracleUnlocked'],
    reason: 'Dated audit (March 11, 2026) of an earlier contract generation: the names and code quotes are that revision\'s, and the document is bannered as historical context rather than a description of the current system.',
    marker: 'retained as historical security context',
  },
  'docs/SECURITY_AUDIT_RESULTS.md': {
    names: ['case:CallHook', 'case:CallVerifier', 'case:CanConfigureHook', 'case:CanConfigureVerifier', 'case:ConfirmHookUpdate', 'case:ConfirmVerifierUpdate', 'case:CreateListing', 'case:ExecuteUserOp', 'case:FinalizeEscape', 'case:InitiateEscape', 'case:RegisterAccount', 'case:RotateAdmin', 'case:SetDailyLimit', 'case:SetHooks', 'case:SetSessionKey', 'case:SettleListing', 'case:SettleMarketEscrow', 'case:UpdateHook', 'case:UpdateListingPrice', 'case:UpdateVerifier', 'case:ValidateSignature', 'entrypoint:IsAnyExecutionActive'],
    reason: 'Dated audit (2026-03-29): the finding sections preserve original evidence, status labels and code snippets of the audited revision, and the status note says not to read the snippets as a description of the deployed artifact.',
    marker: 'some original code snippets/status labels are intentionally historical',
  },
  'frontend/src/assets/docs/SECURITY_AUDIT.md': {
    names: ['case:CanExecuteHook', 'case:SettleMarketEscrow', 'case:ValidateSignature', 'entrypoint:IsAnyExecutionActive', 'entrypoint:IsDomeOracleUnlocked'],
    reason: 'The rendered copy of the dated March 11, 2026 audit: the guard requires this file to equal docs/SECURITY_AUDIT.md byte for byte, so its entries stand or fall with that file and its historical banner.',
    marker: 'retained as historical security context',
  },
};

// Framework and service calls that share a name with a contract method but are not one.
// ContractManagement is the Neo native contract: contracts/UnifiedSmartWallet.Accounts.cs:404 calls
// ContractManagement.GetContract and tests/AbstractAccount.Contracts.Tests/*.cs invoke the native
// "getContract" by string, so a document that reads a NEF back that way names no AA entrypoint.
// CallFlags is the SmartContract.Framework enum used as the third argument of Contract.Call; it is a
// type, not an entrypoint, and naming it here is what keeps the scan's vocabulary from being widened
// entry by entry (DS-CU-210 section 3).
const FRAMEWORK_RECEIVERS = new Set(['Runtime', 'Contract', 'ContractManagement', 'System', 'CryptoLib', 'Storage', 'Helper', 'ExecutionEngine', 'Neo', 'CallFlags']);
// Inline code that looks like an entrypoint but is a parameter, a field or a service name.
// callHash is a field of the pending-module-call record (contracts/UnifiedSmartWallet.Models.cs:65),
// not a callable; DS-CU-202 section 4.
const NON_CALLABLES = new Set(['create_aa_draft', 'claimCommitment', 'callData', 'signMessage', 'getPending', 'callHash']);

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
  // A client factory returns the SDK surface as an object literal: sdk/js/src/multisig.js:24-33
  // exposes buildBundle, buildChildConfiguration, buildChildTypedData and the rest as `name: value`
  // keys, so a documented call to one of them is a real SDK method. The scan is limited to sdk/js/src
  // because the native client's descriptor table (NATIVE_REQUIRED_ABI) has the same key shape.
  if (file.startsWith('sdk/js/src/')) {
    for (const match of text.matchAll(/^\s{2,}([A-Za-z_]\w*):\s*(?:async\s*)?(?=\(|tools\.|[A-Za-z_]\w*\()/gm)) sdkMethods.add(match[1]);
  }
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

// MEASUREMENT BOUNDARY. The patterns below and in the ratchet read INLINE-CODE SPANS only: a call
// inside `backticks` is a name reference, and the same call written as raw code inside a fenced block
// is not. That is how docs/TRANSACTION_FLOW.md and docs/TRANSACTION_LAYOUTS.md carried 33 dead names
// past this ratchet until CU-202 deleted them (DS-CU-202-20261009.md finding F3, re-filed as
// RV-DSCU202R1-r1 minor), so wherever the fenced measurement is absent this count is a FLOOR, not
// the repository's drift. Row CU-210 owns that measurement and separates a fenced claim from a
// fenced mention (DS-CU-210-20261009.md); it reads fences, it does not widen this reader. The test
// "CU-202: the ratchet reads inline-code spans and declares the boundary it does not cross" holds
// both halves of this note, and holds this note itself: delete it and that test fails.

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

// ---------------------------------------------------------------------------------------------
// Fenced code blocks. The ratchet above reads inline-code spans, so a dead name inside a fence was
// invisible by construction: CU-202 (finding F3) lost 33 dead names between two V2 documents that
// way. The scan below reads fences too, and it separates a mention from a claim, because the two
// need opposite treatment (DS-CU-210 section 3):
//
//   a CLAIM is a name the block presents as something to call or to look up on the current runtime:
//   `name(` in code position, a `name:` value in the definition list of a doc example, a quoted
//   method argument of Contract.Call, or a `public static <ret> Name(` definition.
//   A claim whose name the repository does not contain is drift and must be corrected.
//
//   a MENTION is a bare identifier with no call syntax - a mermaid state or node label, a field, a
//   type, a variable. It asserts nothing about the ABI, so it is recorded in V2_FENCE_MENTIONS with
//   the reason it stays instead of being counted as a claim. This is why `HasID` or `CallCustom` in
//   a flowchart is not debt while `IsAnyExecutionActive()` in a C# block is.
//
// Two document-level mechanisms bound the rule, both existing ones: a line that marks the name
// removed, and a `## ... historical` section. A third is new and is visible in the document itself:
// an annotation `<!-- docs-truth: no fence claims for <lang>; reason: ... -->` declares that fenced
// blocks in the named languages are illustrations of another runtime, not claims about this one.
// The annotation must name its languages from the vocabulary below, must not name a Neo language,
// and must carry a reason, so it can silence only the family it states and never "everything".
const DIAGRAM_LANGUAGES = new Set(['mermaid', 'dot', 'graphviz', 'text', 'ascii']);
const NEO_FENCE_LANGUAGES = new Set(['csharp', 'cs']);
const ILLUSTRATIVE_LANGUAGES = new Set(['solidity', 'typescript', 'javascript', 'js', 'python', 'java', 'go', 'rust', 'bash', 'shell', 'sh', 'sql', 'yaml', 'yml', 'json', 'toml', 'ini', 'dockerfile', 'powershell', 'html', 'css', 'xml', 'graphql']);
const NO_FENCE_CLAIMS = /<!--\s*docs-truth:\s*no fence claims for ([a-z0-9, ]+);\s*reason:\s*(.+?)\s*-->/g;
// A dated snapshot declares in its own words that its code snippets are evidence of the revision it
// audited, not a description of what ships. The declaration is a fixed phrase so it can be checked,
// and a document that carries one is registered in V2_FENCE_SCOPES with a reason: the exemption is
// never available implicitly, and a new document cannot adopt it without the guard's list changing.
const HISTORICAL_SNIPPET_SCOPE = /retained as historical security context|as a description of the deployed artifact/i;

// A name is live here exactly when the `entrypoint:` pattern of the ratchet treats it as live, so
// the fence scan widens the measurement without widening any allowance.
function isLiveName(name, file) {
  if (deployedAbi.has(name) || definedNames.has(name) || sdkMethods.has(name)) return true;
  if (NATIVE_PROFILE_DOCS.includes(file) && nativeAbiNames.has(name)) return true;
  return false;
}

// The names a single fenced line asserts. `claim` is a property of the line's own syntax, so a
// definition spread over two lines (a C# signature with its parameters on the next line) declares
// itself on the line that carries the name.
function fenceClaims(line) {
  const names = new Set();
  for (const match of line.matchAll(/([A-Za-z_]\w*)\s*\(/g)) names.add(match[1]);
  for (const match of line.matchAll(/\b(?:operation|method|entrypoint|function|func)\s*:\s*['"]([A-Za-z_]\w*)['"]/gi)) names.add(match[1]);
  for (const match of line.matchAll(/["']([A-Za-z_]\w*)["']\s*,\s*(?:CallFlags|CallPermission)/g)) names.add(match[1]);
  for (const match of line.matchAll(/(?:public|private|internal|protected)\s+static\s+(?:[\w<>[\],.?]+\s+)?([A-Za-z_]\w*)\s*\(/g)) names.add(match[1]);
  for (const match of line.matchAll(/DisplayName\("([^"]+)"\)/g)) names.add(match[1]);
  return [...names].filter((name) => ENTRYPOINT.test(name[0].toLowerCase() + name.slice(1))
    && !FRAMEWORK_RECEIVERS.has(name) && !NON_CALLABLES.has(name));
}

// What the fenced scan finds, as data: { claims: { file: [names] }, mentions: { file: [names] } }.
// Kept as a function, not as assertions, so the planted-drift test can call it on a temporary copy
// of a document and see exactly what the guard would report.
function fenceScan() {
  const claims = {};
  const mentions = {};
  const snippetScopes = new Set();
  const files = tracked.filter((file) => file.endsWith('.md')
    && !file.startsWith('docs/proposals/') && !file.startsWith('docs/reports/') && !file.startsWith('docs/plans/')
    && !CURRENT_DOCS.includes(file));
  for (const file of files) {
    const text = read(file);
    const lines = text.split('\n');
    const historical = historicalSections(lines);
    // The scope note sits in the document's preamble, so it applies to the snippets after it; the
    // pre-pass keeps that order-independent rather than making the note's position load-bearing.
    const snippetScope = HISTORICAL_SNIPPET_SCOPE.test(text.replace(/\s+/g, ' '));
    if (snippetScope) snippetScopes.add(file);
    const exempt = new Set();
    for (const match of text.matchAll(NO_FENCE_CLAIMS)) {
      const languages = match[1].split(',').map((entry) => entry.trim()).filter(Boolean);
      for (const language of languages) {
        assert.ok(ILLUSTRATIVE_LANGUAGES.has(language),
          `${file}: the no-fence-claims annotation names "${language}", which is not an illustrative (non-Neo) language`);
        exempt.add(language);
      }
      assert.ok(match[2].length >= 40, `${file}: the no-fence-claims annotation needs a reason it must stay`);
    }
    for (const language of exempt) {
      assert.ok(!NEO_FENCE_LANGUAGES.has(language),
        `${file}: the no-fence-claims annotation covers "${language}", a Neo language a claim can be written in`);
    }
    let info = null;
    lines.forEach((line, index) => {
      if (/^\s*```/.test(line)) {
        info = info === null ? line.trim().replace(/^```/, '').trim() : null;
        return;
      }
      if (info === null) return;
      const language = info.split(/[\s{:]/)[0].toLowerCase();
      if (exempt.has(language) || snippetScope) return;
      if (REMOVED.test(line) || historical[index]) return;
      // A bare identifier is recorded as a mention only in a diagram: a flowchart or state diagram
      // has a reason to name things that are not called (a node, a state), while a bare identifier
      // in a code block is a variable or a field. Call syntax is a claim in both, which is why a
      // state label reading `InitiateEscape()` is reported and `HasID` inside `class … decision`
      // is recorded instead of being read as an entrypoint.
      if (DIAGRAM_LANGUAGES.has(language)) {
        for (const match of line.matchAll(/\b([A-Za-z_]\w*)\b/g)) {
          const name = match[1];
          if (!ENTRYPOINT.test(name[0].toLowerCase() + name.slice(1))) continue;
          if (FRAMEWORK_RECEIVERS.has(name) || NON_CALLABLES.has(name)) continue;
          if (isLiveName(name, file)) continue;
          if (!mentions[file]) mentions[file] = new Set();
          mentions[file].add(name);
        }
      }
      for (const name of fenceClaims(line)) {
        if (isLiveName(name, file)) continue;
        (claims[file] ??= []).push(name);
      }
    });
  }
  const sorted = (map) => Object.fromEntries(Object.entries(map)
    .map(([file, names]) => [file, [...names].sort()])
    .sort(([a], [b]) => a.localeCompare(b)));
  return { claims: sorted(claims), mentions: sorted(mentions), snippetScopes: [...snippetScopes].sort() };
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

// DS-CU-202 finding F3, filed again as RV-DSCU202R1-r1 (minor): the name patterns read INLINE-CODE
// SPANS only, so a dead name written as raw code inside a fenced block is invisible. The boundary is
// measured in both directions here, and the guard has to declare it where the measurement happens,
// because the ratchet's count is a floor while the boundary stands. Row CU-210 owns the fenced
// measurement (DS-CU-210-20261009.md); this test does not approve the boundary, it refuses to let it
// stay silent.
test('CU-202: the ratchet reads inline-code spans and declares the boundary it does not cross', () => {
  // The boundary: raw code, the shape a fenced block carries, is not a span.
  assert.deepEqual(callableNames('const accountId = executeLegacyControlThing(accountId);'), [],
    'the inline reader must not read raw code as a name reference; if this fails the boundary moved and every count below it is wrong');
  // The same dead name inside one inline span is read, so the boundary is the span, not the name.
  assert.deepEqual(
    callableNames('stop calling `executeLegacyControlThing(accountId)`; it is gone').map((entry) => entry.name),
    ['executeLegacyControlThing'],
    'the same name inside an inline span must be read, or the declared boundary is not where the guard reads');
  // The declaration, at the measurement site: deleting it has to fail here rather than silently widen
  // the ratchet's claim to be the repository's drift. The note is matched with its comment markers
  // and line wrapping normalised, so reflowing it is free and removing it is not.
  const declaration = read('frontend/tests/docsTruth.test.js').match(/\/\/ MEASUREMENT BOUNDARY[\s\S]*?(?=\n\n)/);
  assert.ok(declaration, 'the guard must declare the inline-span measurement boundary where it measures (DS-CU-202 F3)');
  const note = declaration[0].replace(/^\/\/ ?/gm, ' ').replace(/\s+/g, ' ');
  assert.match(note, /INLINE-CODE SPANS only/i, 'the declaration must state the boundary it draws');
  assert.match(note, /CU-210/, 'the declaration must name the row that owns the fenced measurement');
});

// ---------------------------------------------------------------------------------------------
// The gitleaks configuration, held as a whole set
//
// RV-AAADSCU202R2-r1 (major): round two validated ONE [[allowlists]] block - the first whose text
// mentions sdk-usage - and said nothing about the rest of the file. A second allowance block
// carrying global paths and regexes could therefore be appended and all eight tests still passed
// while gitleaks stopped reporting a planted secret. Round 3 measures the whole family
// (DS-CU-202-20261009.md, "Round 3"): a second block, a global path, a global regex, a rule-level
// allowance, a commit allowlist, a stopword, a redefined rule, a configuration reached through
// [extend] path, an .gitleaksignore entry and a nested configuration all suppress findings, and
// most of them also passed the round-two guard. The property is not "this block is scoped" but
// "every suppression the scanner resolves from this repository's tree is one the review triaged"
// (DEC-DS-9: refuse for the property, not by accident of the pattern). The declaration below is
// that triage: the guard parses the file into suppression carriers, holds the whole set to the
// declaration, refuses every carrier the declaration does not name - by kind and by block - and
// binds each declared entry to one file and one value with controls derived from the repository
// rather than from the declaration.
//
// The choice, stated: the guard rejects ANY allowance it did not review rather than permitting a
// bounded set of "scoped-looking" new ones, because a scoped-looking allowance is exactly what the
// round-one sdk-usage block was, and nothing in a block's shape distinguishes a triaged
// suppression from an untriaged one. The cost is deliberate friction: a new triage has to be added
// here, in the same commit, where a reviewer sees it as a change to the reviewed inventory. Values
// are compared by value, so reformatting or re-quoting the configuration is free.
// ---------------------------------------------------------------------------------------------
const GITLEAKS_CONFIG = '.gitleaks.toml';
// Every file name gitleaks resolves a configuration or an ignore set from, anywhere in the tree.
const GITLEAKS_CONFIG_FILES = ['.gitleaks.toml', '.gitleaksignore'];
// The keys the reviewed form of an allowance carries. Any other suppression key (`commits`,
// `stopwords`, ...) is a lever this review did not triage and is reported rather than ignored.
const ALLOWLIST_REVIEWED_KEYS = ['targetRules', 'condition', 'paths', 'regexTarget', 'regexes'];
const ALLOWLIST_KNOWN_KEYS = [...ALLOWLIST_REVIEWED_KEYS, 'commits', 'stopwords'];
// An allowance that names a line of a document is derived from that document, so the guard holds
// the reviewed line without keeping a copy of it: `^[[:space:]]*<the line as written>[[:space:]]*$`.
// The reviewed line is the one `const <identifier> = '...'` assignment the document carries; zero or
// two mean the reviewed line is gone, and the set comparison below then refuses the configuration.
// A document that re-spells the assignment is refused too, which is friction a reviewer sees rather
// than a silent re-scope.
function reviewedLineRegex(relative, identifier) {
  const carried = read(relative).split('\n')
    .filter((line) => new RegExp(`^[ \\t]*const ${identifier} = '`).test(line));
  return carried.length === 1 ? [`^[[:space:]]*${escapeRegex(carried[0].trim())}[[:space:]]*$`] : [];
}

const reviewedAllowlists = () => [
  {
    id: 'morpheus-golden-envelope-keypair',
    fields: {
      targetRules: ['generic-api-key'],
      condition: 'AND',
      paths: ['^sdk/js/tests/morpheus-envelope-roundtrip\\.unit\\.test\\.js$'],
      regexTarget: 'match',
      regexes: ["^GOLDEN_PRIVATE_KEY_PKCS8 = 'MC4CAQAwBQYDK2VuBCIEI[A-Za-z0-9+/]{43}'$"],
    },
    literalPath: 'sdk/js/tests/morpheus-envelope-roundtrip.unit.test.js',
    // What gitleaks hands to the regex under regexTarget = "match": the assignment without the
    // surrounding statement, which is the form the reviewed value was triaged in (DS-CU-163
    // section 12.4).
    matchOf: (line) => (line.match(/\bGOLDEN_PRIVATE_KEY_PKCS8 = '[^']*'/) || [])[0],
    // The declared boundary, asserted in both directions: the identifier, the DER prefix and the
    // width are pinned; the 43 characters of key material are not, because pinning them would copy
    // a private key into the guard. Another identifier, another prefix or another width is
    // reported; a different key under the reviewed identifier is allowed on purpose.
    accepts: [`GOLDEN_PRIVATE_KEY_PKCS8 = 'MC4CAQAwBQYDK2VuBCIEI${'A'.repeat(43)}'`],
    rejects: [
      { why: 'the same key material under a different identifier', line: `GOLDEN_OTHER_KEY_PKCS8 = 'MC4CAQAwBQYDK2VuBCIEI${'A'.repeat(43)}'` },
      { why: 'a different DER prefix under the reviewed identifier', line: `GOLDEN_PRIVATE_KEY_PKCS8 = 'MC4CAQAwBQYDK2VuBCIF${'A'.repeat(43)}'` },
      { why: 'a shorter key than the reviewed width', line: `GOLDEN_PRIVATE_KEY_PKCS8 = 'MC4CAQAwBQYDK2VuBCIEI${'A'.repeat(42)}'` },
    ],
  },
  {
    id: 'web3auth-verifier-hash',
    fields: {
      targetRules: ['generic-api-key'],
      condition: 'AND',
      paths: ['^frontend/src/assets/docs/sdk-usage\\.md$'],
      regexTarget: 'line',
      // The reviewed line, read out of the document rather than copied here: a guard that carries
      // the value it allows is a second copy of that value, and this branch's own canonical scan
      // has to stay clean (DS-CU-202 round 3). An empty list means the document no longer carries
      // the reviewed line, and the set comparison below refuses the configuration for it.
      regexes: reviewedLineRegex('frontend/src/assets/docs/sdk-usage.md', 'web3AuthVerifierHash'),
    },
    literalPath: 'frontend/src/assets/docs/sdk-usage.md',
    matchOf: (line) => line,
    accepts: null,
    // The reviewed line is read from the document, so these controls cannot drift from it. The
    // value must also still be one the registry carries (the round-two control).
    rejects: null,
    canonicalValue: /\b0x[0-9a-fA-F]{40}\b/,
  },
];

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// One line of TOML, with comments removed and triple-quoted strings kept whole. `open` carries a
// triple quote that is still open at the end of the line, so a multi-line description can never
// hide a table header or a key from this parser.
function scanTomlLine(raw) {
  let code = '';
  let open = null;
  for (let index = 0; index < raw.length;) {
    const three = raw.slice(index, index + 3);
    if (three === "'''" || three === '"""') {
      code += three;
      open = open === three ? null : open || three;
      index += 3;
      continue;
    }
    if (!open && raw[index] === '#') break;
    code += raw[index];
    index += 1;
  }
  return { code, open };
}

function tomlStatements(text) {
  const statements = [];
  let open = null;
  for (const raw of text.split('\n')) {
    if (open) {
      if (raw.includes(open)) open = null;
      statements.push('');
      continue;
    }
    const scanned = scanTomlLine(raw);
    if (scanned.open) open = scanned.open;
    statements.push(scanned.code);
  }
  return statements;
}

function splitTomlList(inner) {
  const items = [];
  let current = '';
  let open = null;
  for (let index = 0; index < inner.length;) {
    const three = inner.slice(index, index + 3);
    if (three === "'''" || three === '"""') {
      open = open === three ? null : open || three;
      current += three;
      index += 3;
      continue;
    }
    if (!open && (inner[index] === '"' || inner[index] === "'")) { open = inner[index]; current += inner[index]; index += 1; continue; }
    if (!open && inner[index] === ',') { items.push(current); current = ''; index += 1; continue; }
    current += inner[index];
    index += 1;
  }
  if (current.trim()) items.push(current);
  return items.map((item) => item.trim()).filter((item) => item !== '');
}

// Values are compared by value, not by spelling: quoting style, whitespace, a trailing comma or a
// different key order do not change what gitleaks suppresses, so they must not change this verdict.
function parseTomlValue(raw) {
  const value = raw.trim();
  if (value.startsWith('[')) {
    return splitTomlList(value.slice(1, value.lastIndexOf(']'))).map((item) => parseTomlValue(item));
  }
  for (const quote of ["'''", '"""', '"', "'"]) {
    if (value.length >= 2 * quote.length && value.startsWith(quote) && value.endsWith(quote)) {
      return value.slice(quote.length, value.length - quote.length);
    }
  }
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value;
}

// The whole file as suppression carriers. Every table the review did not triage is a carrier too:
// [allowlist] and [[rules.allowlists]] suppress findings just as [[allowlists]] does.
function parseGitleaksConfig(text) {
  const parsed = {
    topLevel: new Map(), allowlists: [], legacyTables: [], ruleBlocks: [],
    ruleAllowlists: [], otherTables: [], extend: new Map(), extendAt: 0,
  };
  let current = null;
  tomlStatements(text).forEach((line, index) => {
    const at = index + 1;
    const trimmed = line.trim();
    if (!trimmed) return;
    const header = trimmed.match(/^\[\[?([^\]]+?)\]\]?$/);
    if (header) {
      const name = header[1].trim();
      if (name === 'allowlists') { current = { kind: 'allowlist', name, fields: new Map(), at }; parsed.allowlists.push(current); return; }
      if (name === 'allowlist') { current = { kind: 'legacy', name, fields: new Map(), at }; parsed.legacyTables.push(current); return; }
      if (name === 'rules') { current = { kind: 'rule', name, fields: new Map(), at }; parsed.ruleBlocks.push(current); return; }
      if (name === 'rules.allowlists' || name === 'rules.allowlist') {
        current = { kind: 'rule-allowlist', name, fields: new Map(), at };
        parsed.ruleAllowlists.push(current);
        return;
      }
      if (name === 'extend') { current = { kind: 'extend', name, fields: parsed.extend, at }; parsed.extendAt = at; return; }
      current = { kind: 'other', name, fields: new Map(), at };
      parsed.otherTables.push(current);
      return;
    }
    const assignment = trimmed.match(/^([A-Za-z_][\w.-]*)\s*=\s*([\s\S]*)$/);
    if (!assignment) return;
    const [, key, rawValue] = assignment;
    if (!current) parsed.topLevel.set(key, parseTomlValue(rawValue));
    else current.fields.set(key, parseTomlValue(rawValue));
  });
  return parsed;
}

const canonicalAllowlist = (fields) => JSON.stringify(Object.fromEntries(
  [...ALLOWLIST_KNOWN_KEYS].sort().filter((key) => fields.has(key)).map((key) => [key, fields.get(key)])));

const sameAllowlist = (entry, block) => canonicalAllowlist(new Map(Object.entries(entry.fields))) === canonicalAllowlist(block.fields);

const describeAllowlist = (block) => `${block.fields.has('paths') ? `paths ${JSON.stringify(block.fields.get('paths'))}` : 'no path'}`
  + `${block.fields.has('regexes') ? `, regexes ${JSON.stringify(block.fields.get('regexes'))}` : ', no regex'}`
  + `${block.fields.has('description') ? `, "${String(block.fields.get('description')).slice(0, 60)}"` : ''}`;

// Every configuration or ignore file in the tree that is not the reviewed one. A nested
// .gitleaks.toml is inert only while every scan is rooted at the repository; the guard refuses it
// rather than depending on how a scan is invoked.
function otherGitleaksFiles() {
  const found = [];
  (function walk(dir) {
    for (const entry of fs.readdirSync(path.join(repoRoot, dir), { withFileTypes: true })) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const relative = path.join(dir, entry.name);
      if (entry.isDirectory()) { if (!entry.name.startsWith('.')) walk(relative); continue; }
      if (GITLEAKS_CONFIG_FILES.includes(entry.name) && relative !== GITLEAKS_CONFIG) found.push(relative);
    }
  })('.');
  return found.sort();
}

// The reported set. An empty array is the only accepting verdict; every entry names the carrier it
// refuses and the line it sits on. Nothing here reports a boolean or an exit code, so a mutant can
// only be killed by a violation that names it.
function configurationViolations(text, files = otherGitleaksFiles()) {
  const problems = [];
  const add = (kind, detail) => problems.push(`${kind}: ${detail}`);
  if (!text.trim()) {
    add('missing-configuration', `${GITLEAKS_CONFIG} is absent; the reviewed allowances are not the ones a scan would apply`);
    return problems;
  }
  const parsed = parseGitleaksConfig(text);
  for (const table of parsed.legacyTables) {
    add('legacy-singular-table', `${GITLEAKS_CONFIG}:${table.at} uses [allowlist], the pre-8.19 table this review did not triage; alone it suppresses globally, and gitleaks refuses it beside [[allowlists]]`);
  }
  for (const block of parsed.ruleBlocks) {
    add('rule-override', `${GITLEAKS_CONFIG}:${block.at} redefines a rule ([[rules]]); a redefinition can drop a default rule's detection or carry its own allowance`);
  }
  for (const block of parsed.ruleAllowlists) {
    add('rule-scoped-allowlist', `${GITLEAKS_CONFIG}:${block.at} attaches an allowance to one rule ([${block.name}]), a placement this review did not triage`);
  }
  for (const table of parsed.otherTables) {
    add('unknown-table', `${GITLEAKS_CONFIG}:${table.at} carries [${table.name}], which the reviewed configuration does not`);
  }
  for (const [key, value] of parsed.topLevel) {
    if (['minVersion', 'maxVersion', 'title', 'description'].includes(key)) continue;
    add('unreviewed-key', `${GITLEAKS_CONFIG} sets the top-level ${key} = ${JSON.stringify(value)}, which the reviewed configuration does not`);
  }
  if (parsed.extend.has('path')) {
    add('extend-path', `${GITLEAKS_CONFIG}:${parsed.extendAt} reaches another configuration through [extend] path = ${JSON.stringify(parsed.extend.get('path'))}; that file is outside this guard's inventory`);
  }
  if (!parsed.extend.has('useDefault')) {
    add('defaults-missing', `${GITLEAKS_CONFIG} does not set [extend] useDefault = true; the default rules are the detection this configuration must keep`);
  } else if (parsed.extend.get('useDefault') !== true) {
    add('defaults-disabled', `${GITLEAKS_CONFIG}:${parsed.extendAt} sets [extend] useDefault = ${JSON.stringify(parsed.extend.get('useDefault'))}; the default rules are the detection this configuration must keep`);
  }
  const remaining = [...reviewedAllowlists()];
  parsed.allowlists.forEach((block) => {
    for (const key of block.fields.keys()) {
      if (key === 'description' || ALLOWLIST_REVIEWED_KEYS.includes(key)) continue;
      add('unreviewed-field', `${GITLEAKS_CONFIG}:${block.at} sets ${key} inside a [[allowlists]] block; the reviewed form carries only ${ALLOWLIST_REVIEWED_KEYS.join(', ')}`);
    }
    const at = remaining.findIndex((entry) => sameAllowlist(entry, block));
    if (at === -1) {
      add('unreviewed-allowlist', `${GITLEAKS_CONFIG}:${block.at} carries a [[allowlists]] block (${describeAllowlist(block)}) that is not one of the ${reviewedAllowlists().length} allowances this review triaged`);
    } else {
      remaining.splice(at, 1);
    }
  });
  for (const entry of remaining) {
    add('missing-allowlist', `${GITLEAKS_CONFIG} does not carry the reviewed ${entry.id} allowance as reviewed; every suppression the scanner applies must be one the review triaged`);
  }
  for (const file of files) {
    add('extra-configuration', `${file} is a gitleaks configuration or ignore file outside the reviewed ${GITLEAKS_CONFIG}`);
  }
  return problems;
}

const violationKinds = (problems) => [...new Set(problems.map((problem) => problem.split(':')[0]))].sort();

const configurationProblems = () => configurationViolations(exists(GITLEAKS_CONFIG) ? read(GITLEAKS_CONFIG) : '');

// The reviewed allowances, each held to one file and one value, with both directions of that
// boundary asserted. DS-CU-163 section 12.4 established the shape with planted secrets in a clone;
// here it runs against the repository copy itself, for every entry rather than for one.
test('CU-202: every reviewed allowance stays attached to the one value it triaged', () => {
  assert.ok(reviewedAllowlists().length > 0, 'the reviewed allowance inventory must not be empty');
  for (const entry of reviewedAllowlists()) {
    const where = entry.id;
    assert.equal(entry.fields.targetRules.length, 1, `${where}: the allowance must suppress exactly one rule`);
    assert.equal(entry.fields.condition, 'AND', `${where}: every clause of the allowance must have to match`);
    assert.ok(['line', 'match'].includes(entry.fields.regexTarget), `${where}: the allowance must constrain a reviewed target, not ${entry.fields.regexTarget}`);
    // The path half: one file, named literally, with no pattern power and no second match anywhere
    // in the tree. A wildcard, a missing anchor or a prefix match breaks the equality below.
    assert.equal(entry.fields.paths.length, 1, `${where}: the allowance must name exactly one path`);
    assert.equal(entry.fields.paths[0], `^${escapeRegex(entry.literalPath)}$`,
      `${where}: the path clause must be the literal path and nothing else`);
    const pathRegex = new RegExp(entry.fields.paths[0]);
    const reached = tracked.filter((file) => pathRegex.test(file));
    assert.deepEqual(reached, [entry.literalPath], `${where}: the path clause must reach exactly the one file it triages`);
    // The value half: one anchored regex, matching the reviewed assignment in its own document.
    // gitleaks reads Go's regexp, where [[:space:]] is a POSIX class JavaScript does not carry, so
    // that one class is translated; any other POSIX class fails here instead of being read wrongly.
    assert.equal(entry.fields.regexes.length, 1, `${where}: the allowance must carry exactly one value regex`);
    const source = entry.fields.regexes[0];
    assert.match(source, /^\^[\s\S]*\$$/, `${where}: the value regex must be anchored at both ends`);
    assert.ok(!/\[\[:(?!space:\]\])/.test(source), `${where}: the allowance uses a POSIX class this test cannot translate`);
    const pattern = new RegExp(source.replace(/\[\[:space:\]\]/g, '[ \\t]'));
    const matchesLine = (line) => {
      const target = entry.matchOf(line);
      return typeof target === 'string' && pattern.test(target);
    };
    const covered = read(entry.literalPath).split('\n').filter(matchesLine);
    assert.equal(covered.length, 1, `${where}: the allowance must match exactly one line of the document it triages; it matches ${covered.length}`);
    if (entry.canonicalValue) {
      const value = covered[0].match(entry.canonicalValue)[0];
      assert.ok(canonicalHashes.has(value.toLowerCase()),
        `${where}: the allowed value ${value} must be the canonical registry hash, not a value generatedMorpheusRegistry.js does not carry`);
    }
    for (const accepted of entry.accepts || [covered[0]]) {
      assert.ok(matchesLine(accepted), `${where}: the allowance must still cover the assignment it triages`);
    }
    const rejected = entry.rejects || [
      { why: 'a different value on the reviewed line (the DS-CU-163 section 12.4 control)', line: covered[0].replace(/\b0x[0-9a-fA-F]{40}\b/, '0x9f2c41ab77de05361c8b0e4a6d5f31c7b8a2e904') },
      { why: 'the same value under a different identifier', line: covered[0].replace('web3AuthVerifierHash', 'otherVerifierHash') },
    ];
    for (const control of rejected) {
      assert.ok(!matchesLine(control.line), `${where}: ${control.why} must still be reported`);
    }
  }
});

test('CU-202: the gitleaks configuration carries the reviewed allowance set and nothing else', () => {
  const problems = configurationProblems();
  assert.deepEqual(problems, [], `the gitleaks configuration carries suppressions the review did not triage:\n${problems.join('\n')}`);
});

// One mutant per widening shape, taken from the reviewed text itself. Each is refused by a
// violation that names the shape it adds, and the assertion is on the reported set, so no kill is
// incidental and none is read off an exit code.
test('CU-202: every widening of the gitleaks configuration is refused by the shape it adds', () => {
  const base = read(GITLEAKS_CONFIG);
  const appended = (text) => `${base}\n${text}`;
  // Literal replacement, every occurrence: the reviewed value appears in the block's comment as
  // well as in its regex, and a mutant that only rewrote the comment would not be a mutant.
  const replaced = (from, to) => base.split(from).join(to);
  const sdkBlock = base.split('[[allowlists]]').find((entry) => entry.includes('sdk-usage'));
  assert.ok(sdkBlock, 'the reviewed sdk-usage allowance must be in the configuration for these mutants to mean anything');
  const inSdkBlock = (from, to) => base.replace(sdkBlock, () => sdkBlock.split(from).join(to));
  // A mutant that removes a whole field of the reviewed block, addressed by its key rather than by
  // its value, so this test carries no copy of the value the allowance triages.
  const withoutSdkField = (key) => base.replace(sdkBlock, () => sdkBlock.split('\n')
    .filter((line) => !line.trimStart().startsWith(`${key} = `)).join('\n'));
  const shapes = [
    { name: 'control: the reviewed configuration', text: base, kinds: [] },
    { name: 'a second allowance block, global on paths and regexes', text: appended("\n[[allowlists]]\ndescription = \"mutant: a global allowance\"\npaths = ['''.*''']\nregexes = ['''.*''']\n"), kinds: ['unreviewed-allowlist'], names: 'a global allowance' },
    { name: 'a second allowance block, global path only', text: appended("\n[[allowlists]]\ndescription = \"mutant: a global path\"\npaths = ['''.*''']\n"), kinds: ['unreviewed-allowlist'], names: 'a global path' },
    { name: 'a second allowance block, global regex only', text: appended("\n[[allowlists]]\ndescription = \"mutant: a global regex\"\nregexes = ['''.*''']\n"), kinds: ['unreviewed-allowlist'], names: 'a global regex' },
    { name: 'a second allowance block, one rule named but a global regex', text: appended("\n[[allowlists]]\ndescription = \"mutant: rule-scoped global regex\"\ntargetRules = [\"generic-api-key\"]\nregexes = ['''.*''']\n"), kinds: ['unreviewed-allowlist'], names: 'rule-scoped global regex' },
    { name: 'a second allowance block, an empty path regex', text: appended("\n[[allowlists]]\ndescription = \"mutant: empty path\"\npaths = ['''''' ]\n"), kinds: ['unreviewed-allowlist'], names: 'empty path' },
    { name: 'a commit allowlist', text: appended("\n[[allowlists]]\ndescription = \"mutant: commit allowlist\"\ncommits = [\"a64f88968d43fb7daca25ecd2f6965e96d194c59\"]\n"), kinds: ['unreviewed-allowlist', 'unreviewed-field'], names: 'commits inside a [[allowlists]] block' },
    { name: 'a stopword allowance', text: appended("\n[[allowlists]]\ndescription = \"mutant: stopword\"\ntargetRules = [\"generic-api-key\"]\nstopwords = [\"8f3a9c2b\"]\n"), kinds: ['unreviewed-allowlist', 'unreviewed-field'], names: 'stopwords inside a [[allowlists]] block' },
    { name: 'a decoy block that names sdk-usage and is placed first', text: replaced('[[allowlists]]', "[[allowlists]]\ndescription = \"mutant: sdk-usage decoy\"\npaths = ['''.*''']\nregexes = ['''.*''']\n\n[[allowlists]]"), kinds: ['unreviewed-allowlist'], names: 'sdk-usage decoy' },
    { name: 'the pre-8.19 singular table, alone', text: "minVersion = \"v8.30.1\"\n\n[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"mutant: legacy\"\npaths = ['''.*''']\nregexes = ['''.*''']\n", kinds: ['legacy-singular-table', 'missing-allowlist'], names: '[allowlist], the pre-8.19 table' },
    { name: 'a rule redefinition that can never match', text: appended("\n[[rules]]\nid = \"generic-api-key\"\ndescription = \"mutant: rule redefinition\"\nregex = '''nevermatches'''\n"), kinds: ['rule-override'], names: 'redefines a rule' },
    { name: 'a rule-scoped allowance under a new rule', text: appended("\n[[rules]]\nid = \"mutant-rule\"\ndescription = \"mutant: rule scope\"\nregex = '''apiKey'''\n[[rules.allowlists]]\nregexes = ['''.*''']\n"), kinds: ['rule-override', 'rule-scoped-allowlist'], names: '[rules.allowlists]' },
    { name: 'a configuration reached through [extend] path', text: replaced('useDefault = true', 'path = "cu202-extra.toml"'), kinds: ['defaults-missing', 'extend-path'], names: '[extend] path' },
    { name: 'the default rules switched off', text: replaced('useDefault = true', 'useDefault = false'), kinds: ['defaults-disabled'], names: 'useDefault' },
    { name: 'an .gitleaksignore file', text: base, files: ['.gitleaksignore'], kinds: ['extra-configuration'], names: '.gitleaksignore' },
    { name: 'a nested configuration', text: base, files: ['frontend/.gitleaks.toml'], kinds: ['extra-configuration'], names: 'frontend/.gitleaks.toml' },
    { name: 'an unknown top-level key', text: replaced('minVersion = "v8.30.1"', 'minVersion = "v8.30.1"\nkeywords = ["mutant"]'), kinds: ['unreviewed-key'], names: 'keywords' },
    { name: 'an unknown table', text: appended("\n[[mutant-table]]\ndescription = \"mutant: unknown table\"\n"), kinds: ['unknown-table'], names: 'mutant-table' },
    { name: 'a broader value regex inside the reviewed block', text: inSdkBlock("const web3AuthVerifierHash = '", "const \\w+ = '"), kinds: ['missing-allowlist', 'unreviewed-allowlist'], names: 'web3auth-verifier-hash' },
    { name: 'a second target rule inside the reviewed block', text: inSdkBlock('targetRules = ["generic-api-key"]', 'targetRules = ["generic-api-key", "stripe-access-token"]'), kinds: ['missing-allowlist', 'unreviewed-allowlist'], names: 'web3auth-verifier-hash' },
    { name: 'a different regexTarget inside the reviewed block', text: inSdkBlock('regexTarget = "line"', 'regexTarget = "match"'), kinds: ['missing-allowlist', 'unreviewed-allowlist'], names: 'web3auth-verifier-hash' },
    { name: 'OR instead of AND inside the reviewed block', text: inSdkBlock('condition = "AND"', 'condition = "OR"'), kinds: ['missing-allowlist', 'unreviewed-allowlist'], names: 'web3auth-verifier-hash' },
    { name: 'the reviewed block without its path', text: withoutSdkField('paths'), kinds: ['missing-allowlist', 'unreviewed-allowlist'], names: 'no path' },
    { name: 'the reviewed block without its value regex', text: withoutSdkField('regexes'), kinds: ['missing-allowlist', 'unreviewed-allowlist'], names: 'no regex' },
  ];
  for (const shape of shapes) {
    const problems = configurationViolations(shape.text, shape.files || []);
    const kinds = violationKinds(problems);
    assert.deepEqual(kinds, [...shape.kinds].sort(), `${shape.name}: the configuration must be refused for the shapes it adds, and for nothing else:\n${problems.join('\n') || '(nothing reported)'}`);
    if (shape.names) {
      assert.ok(problems.some((problem) => problem.includes(shape.names)),
        `${shape.name}: the refusal must name what it refuses (${shape.names}):\n${problems.join('\n')}`);
    }
  }
});

// The scanner-level direction of the same rule, on a throwaway repository: the reviewed
// configuration still reports a secret nothing triaged, and the widening that would silence it is
// refused by the guard rather than by an exit code. Skipped, explicitly, where gitleaks is absent.
test('CU-202: a planted secret survives the reviewed configuration, and the widening that silences it is refused', (t) => {
  let available = true;
  try {
    execFileSync('gitleaks', ['version'], { stdio: 'pipe' });
  } catch {
    available = false;
  }
  if (!available) return t.skip('gitleaks is not on PATH: the scanner-level direction of this rule is unmeasured in this run');
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'cu202-gitleaks-'));
  const git = (...args) => execFileSync('git', args, { cwd: scratch, stdio: 'pipe' });
  const write = (relative, body) => {
    fs.mkdirSync(path.dirname(path.join(scratch, relative)), { recursive: true });
    fs.writeFileSync(path.join(scratch, relative), body);
  };
  try {
    git('init', '--quiet');
    git('config', 'user.name', 'CU-202');
    git('config', 'user.email', 'cu-202@localhost');
    write(GITLEAKS_CONFIG, read(GITLEAKS_CONFIG));
    git('add', '-A');
    git('commit', '--quiet', '-m', 'base');
    const base = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: scratch, encoding: 'utf8' }).trim();
    // Synthetic, high-entropy key material: it is what the rules report, so every direction below
    // measures a real suppression rather than a value no rule would have found.
    const material = 'Zq7xK2mP9vL4nR8tB3wY6cH1jF5dG0sA9bC2eD4fGh6';
    assert.equal(material.length, 43, 'the probe material must be the 43 characters the reviewed keypair allowance pins');
    // Derived, not written down, so this guard carries no scanner-visible secret of its own: the
    // branch's canonical scan is a gate, and a test that plants a literal secret in itself reds it.
    const probeSecret = createHash('sha256').update('CU-202 round 3 probe').digest('hex').slice(0, 48);
    assert.equal(probeSecret.length, 48, 'the probe secret must be the 48 characters the rule reports');
    // A secret nothing triaged; the reviewed identifier carrying that material; and the same
    // material under an identifier the reviewed allowance does not name.
    write('frontend/src/config/probe.js', `export const apiKey = "${probeSecret}";\n`);
    write('sdk/js/tests/morpheus-envelope-roundtrip.unit.test.js', `const GOLDEN_PRIVATE_KEY_PKCS8 = 'MC4CAQAwBQYDK2VuBCIEI${material}';\n`);
    write('frontend/src/config/probe-key.js', `const GOLDEN_OTHER_KEY_PKCS8 = 'MC4CAQAwBQYDK2VuBCIEI${material}';\n`);
    git('add', '-A');
    git('commit', '--quiet', '-m', 'plant');
    const plant = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: scratch, encoding: 'utf8' }).trim();
    const scan = (label, config) => {
      write(GITLEAKS_CONFIG, config);
      const report = path.join(scratch, `${label}.json`);
      // The canonical invocation this repository documents; the verdict is read from the report
      // rather than from the exit code, because a scan that fails writes no report at all.
      try {
        execFileSync('gitleaks', ['git', '--redact', '--no-banner', '--exit-code', '1', `--log-opts=${base}..${plant}`, '--report-format', 'json', `--report-path=${report}`, '.'], { cwd: scratch, stdio: 'pipe' });
      } catch { /* a finding is the expected outcome of the reviewed run */ }
      assert.ok(fs.existsSync(report), `${label}: the scan produced no report`);
      return (JSON.parse(fs.readFileSync(report, 'utf8')) || []).map((found) => `${found.RuleID} ${found.File}`).sort();
    };
    const reviewedConfig = read(GITLEAKS_CONFIG);
    // Both directions of the reviewed keypair allowance: the shape it triaged is not reported, and
    // the same material under another identifier is.
    assert.deepEqual(scan('reviewed', reviewedConfig), [
      'generic-api-key frontend/src/config/probe-key.js',
      'generic-api-key frontend/src/config/probe.js',
    ], 'the reviewed configuration must still report every secret it did not triage');
    // The direction above is only a suppression if the same line is reported without the
    // allowance: the block is removed and the scan must find it.
    const withoutKeypair = reviewedConfig.split('[[allowlists]]')
      .filter((block, index) => index === 0 || !block.includes('morpheus-envelope-roundtrip')).join('[[allowlists]]');
    assert.ok(!withoutKeypair.includes('morpheus-envelope-roundtrip'), 'the control must actually remove the reviewed keypair allowance');
    assert.deepEqual(scan('without-keypair', withoutKeypair), [
      'generic-api-key frontend/src/config/probe-key.js',
      'generic-api-key frontend/src/config/probe.js',
      'generic-api-key sdk/js/tests/morpheus-envelope-roundtrip.unit.test.js',
    ], 'without the reviewed allowance the fixture line must be reported; otherwise the suppression above proves nothing');
    // The widening the reviewer appended. It silences the scan, which is why the guard has to
    // refuse it: the refusal is asserted on the reported set, and the harm is measured here.
    const widened = `${reviewedConfig}\n[[allowlists]]\ndescription = "reviewer probe: a global allowance"\npaths = ['''.*''']\nregexes = ['''.*''']\n`;
    assert.deepEqual(scan('widened', widened), [], 'the widening must be what silences the scan; if it is not, this measurement is not the reviewer\'s');
    const problems = configurationViolations(widened, []);
    assert.equal(violationKinds(problems).includes('unreviewed-allowlist'), true,
      `the guard must refuse the configuration that silences the scan:\n${problems.join('\n') || '(nothing reported)'}`);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});

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
      // A documented callable the SDK defines is not a dead reference either: the MultiSig guide
      // names client methods (buildBundle, buildChildTypedData) without the `client.` prefix that
      // the sdk rule below requires, and sdk/js/src/multisig.js exposes exactly those.
      .filter(({ name }) => !sdkMethods.has(name))
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
  // The recorded list is exact: a new dead reference, a new document, or an entry that is no longer
  // found all fail. Every recorded entry also has to carry the reason it must stay, and an entry with
  // a marker has to find that marker in its document, so a scope note cannot be deleted silently.
  const recorded = Object.fromEntries(Object.entries(V2_DEBT).map(([file, entry]) => [file, entry.names]));
  assert.deepEqual(found, recorded, 'the V2-era debt list changed: a document drifted, or a corrected document must be removed from the ratchet');
  for (const [file, entry] of Object.entries(V2_DEBT)) {
    assert.ok(entry.reason && entry.reason.length >= 40, `${file}: the ratchet entry needs a reason it must stay`);
    if (entry.marker) {
      assert.ok(exists(file) && read(file).includes(entry.marker),
        `${file}: the justification claims a scope declaration the document no longer carries: ${entry.marker}`);
    }
  }
});

// Fenced blocks whose names the scan judges to be mentions rather than claims. Each entry is a name
// that a diagram uses as a label while the code the label stands for is called by its deployed
// spelling; the arrow of the correction is the other way round from the ratchet, so these are
// recorded here and the guard fails if one disappears rather than if one appears. DS-CU-210 section 4.
const V2_FENCE_MENTIONS = {
  'docs/DATA_FLOW.md': {
    names: ['CallCustom', 'HasID'],
    reason: 'Bare mermaid node labels of the authorization flowchart (HasID is the account-id decision node, CallCustom the verifier branch), not calls; the underlying reads are named in the deployed ABI and the diagram is a picture of the flow, not an example a reader copies.',
  },
  'docs/ETHEREUM_AA_COMPARISON.md': {
    names: ['ValidateSig', 'validateUserOpLogic'],
    reason: 'Bare mermaid node labels in the diagram that maps the Ethereum validation path onto the Neo one (ValidateSig stands for the signature-check stage, validateUserOpLogic for the Ethereum validator logic); neither is written as a call, and the solidity blocks of the same document are already declared illustrative.',
  },
  'docs/NATIVE_ACCOUNT_TRANSACTION_GUARDS.md': {
    names: ['cancelModuleCall'],
    reason: 'The native account work landed on the default branch after this chain forked; its text fence is the NeoVM script the signed application runs, and the name is the AccountManagement method that script pushes as a string, so the document names the call rather than making it.',
  },
  'frontend/src/assets/docs/data-flow.md': {
    names: ['CallCustom', 'HasID'],
    reason: 'The rendered copy of the same flowchart; the rendered documents are required to stay in step with their source, so its mention list stands or falls with docs/DATA_FLOW.md.',
  },
};


// Dated snapshots whose own scope note says their code snippets are evidence of the revision they
// audited rather than a description of the deployed artifact. The guard requires the phrase to be
// present; this list is what lets a document use it, so an exemption is never implicit and adopting
// it in a new document fails the test instead of silencing the scan (DS-CU-210 section 3).
const V2_FENCE_SCOPES = {
  'docs/SECURITY_AUDIT_RESULTS.md': 'Dated audit (2026-03-29) whose status note ends "Do not use the historical snippets below as a description of the deployed artifact": the fenced C# is that revision\'s code, and the document already carries the note as the reason its inline entries stay in the ratchet.',
  'docs/SECURITY_AUDIT.md': 'Dated audit (March 11, 2026) whose summary says it "is retained as historical security context rather than as the sole description of the current system": the same reasoning as the results document, in the file the ratchet already justifies with that marker.',
  'frontend/src/assets/docs/SECURITY_AUDIT.md': 'The rendered copy of the March 11, 2026 audit, required by this guard to equal docs/SECURITY_AUDIT.md byte for byte, so its snippets inherit that document\'s scope note exactly as its ratchet entries already do.',
};

test('CU-210: fenced blocks assert nothing the code does not, and the ratchet still holds', () => {
  const scan = fenceScan();
  assert.deepEqual(scan.claims, {},
    `a fenced block calls a name the repository does not define:\n${JSON.stringify(scan.claims, null, 2)}`);
  const recorded = Object.fromEntries(Object.entries(V2_FENCE_MENTIONS).map(([file, entry]) => [file, entry.names]));
  const recordedSorted = Object.fromEntries(Object.entries(recorded).sort(([a], [b]) => a.localeCompare(b)));
  assert.deepEqual(scan.mentions, recordedSorted,
    'the justified fence mentions changed: a diagram gained a dead label, or a corrected diagram must be removed here');
  for (const [file, entry] of Object.entries(V2_FENCE_MENTIONS)) {
    assert.ok(entry.reason && entry.reason.length >= 40, `${file}: the fence-mention entry needs a reason it must stay`);
  }
  // The scope list is exact: a snapshot may only use the exemption when it says so, and a document
  // that starts saying so must be registered with a reason.
  assert.deepEqual(scan.snippetScopes, Object.keys(V2_FENCE_SCOPES).sort(),
    'the set of documents claiming a historical-snippet scope changed');
  for (const [file, reason] of Object.entries(V2_FENCE_SCOPES)) {
    assert.ok(reason && reason.length >= 40, `${file}: the historical-snippet scope needs a reason it must stay`);
  }
});

// Every rule above must be able to fail, so each one gets a document mutant, run against a temporary
// copy of the tree's document and restored immediately. A mutant that survives means the rule is
// decoration; the messages are asserted, not the exit code, so an incidental failure elsewhere does
// not count as a kill. DS-CU-210 section 6.
test('CU-210: each fenced rule is killed by its planted drift', () => {
  // fenceScan reports; it only throws for a malformed declaration. A mutant therefore kills its rule
  // when the reported claim set changes to include the planted name, and an incidental assertion
  // failure elsewhere is not a kill.
  const mutants = [
    {
      rule: 'a dead call inside a fenced code block is reported (the drift that was invisible before CU-210)',
      file: 'frontend/src/assets/docs/custom-verifiers.md',
      plant: (text) => text.replace("  operation: 'updateVerifier',", "  operation: 'setLegacyVerifierAddress',"),
      claim: 'setLegacyVerifierAddress',
    },
    {
      rule: 'a fenced block cannot show a removed entrypoint as current, and a marked removal silences it',
      file: 'frontend/src/assets/docs/custom-verifiers.md',
      plant: (text) => text.replace("  operation: 'updateVerifier',", "  operation: 'setLegacyVerifierAddress', // removed call, kept as the before example"),
      claim: null,
    },
    {
      rule: 'a definition in a fence is a claim even without a call site',
      file: 'docs/SECURITY_MODEL.md',
      plant: (text) => text.replace('### 9.2 Security Properties', '```csharp\npublic static void InitiateLegacyRecovery(UInt160 accountId)\n```\n\n### 9.2 Security Properties'),
      claim: 'InitiateLegacyRecovery',
    },
    {
      rule: 'a bare identifier in a diagram is recorded as a mention rather than reported as a claim',
      file: 'docs/DATA_FLOW.md',
      plant: (text) => text.replace('HasID{Account ID Valid?}', 'HasLegacyIdCheck{Account ID Valid?}'),
      claim: null,
      mention: 'HasLegacyIdCheck',
    },
    {
      rule: 'the illustrative-language annotation must carry a reason, so it cannot be a bare silence',
      file: 'docs/ETHEREUM_AA_COMPARISON.md',
      plant: (text) => text.replace('reason: the document compares Neo with Ethereum, so every solidity block lists the Ethereum interface (IValidator, IPaymaster, the ECDSA helper), not a Neo entrypoint.', 'reason: short.'),
      throws: /needs a reason/,
    },
    {
      rule: 'the illustrative-language annotation cannot be widened to a Neo language',
      file: 'docs/ETHEREUM_AA_COMPARISON.md',
      plant: (text) => text.replace('no fence claims for solidity;', 'no fence claims for solidity, csharp;'),
      throws: /not an illustrative \(non-Neo\) language/,
    },
  ];
  for (const mutant of mutants) {
    const target = path.join(repoRoot, mutant.file);
    const original = fs.readFileSync(target, 'utf8');
    const planted = mutant.plant(original);
    assert.notEqual(planted, original, `${mutant.rule}: the mutant did not change ${mutant.file}`);
    fs.writeFileSync(target, planted);
    try {
      if (mutant.throws) {
        // assert.throws only tests the error message when the expectation is a function, so the
        // predicate is written out rather than passed as a regex
        assert.throws(() => fenceScan(), (error) => mutant.throws.test(error.message),
          `${mutant.rule}: the planted drift survived`);
        continue;
      }
      const scan = fenceScan();
      if (mutant.claims) {
        // the gate held and the widened exemption did not silence the fence it now covers
        for (const name of mutant.claims) {
          assert.ok(scan.claims[mutant.file]?.includes(name),
            `${mutant.rule}: widening the annotation silenced "${name}" in ${mutant.file}`);
        }
        continue;
      }
      if (mutant.claim) {
        assert.ok(scan.claims[mutant.file]?.includes(mutant.claim),
          `${mutant.rule}: the planted drift survived; the scan reported ${JSON.stringify(scan.claims)}`);
      } else if (mutant.mention) {
        assert.ok(scan.mentions[mutant.file]?.includes(mutant.mention),
          `${mutant.rule}: the planted label was not recorded as a mention`);
        assert.ok(!scan.claims[mutant.file]?.includes(mutant.mention),
          `${mutant.rule}: the planted label was reported as a claim`);
      } else {
        assert.ok(!scan.claims[mutant.file]?.includes('setLegacyVerifierAddress'),
          `${mutant.rule}: a fence the document marks removed was still reported`);
      }
    } finally {
      fs.writeFileSync(target, original);
    }
  }
  // the mutants leave the tree exactly as they found it
  for (const mutant of mutants) {
    const target = path.join(repoRoot, mutant.file);
    assert.ok(!fs.readFileSync(target, 'utf8').includes('setLegacyVerifierAddress'), `${mutant.file} kept a planted drift`);
  }
});

// Dated snapshots whose own scope note says their code snippets are evidence of the revision they
// audited rather than a description of the deployed artifact. The guard requires the phrase to be
