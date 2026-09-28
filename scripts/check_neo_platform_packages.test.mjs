import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PATHS,
  ownerActionMessage,
  parseManifest,
  pinConsistencyProblems,
  readPinnedVersion,
  restoredPackageProblems,
  unavailablePrivatePackages,
} from "./check_neo_platform_packages.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
const manifest = parseManifest(read(PATHS.manifest));

// Captured from `dotnet restore` of the tests project on a clean NuGet cache
// with no feed carrying the private packages (2026-09-28, paths shortened).
const CLEAN_RUNNER_RESTORE = `
  Determining projects to restore...
/w/contracts/UnifiedSmartWallet.csproj : error NU1102: Unable to find package Neo.SmartContract.Framework with version (>= 3.10.2-CI00384) [/w/tests/AbstractAccount.Contracts.Tests/AbstractAccount.Contracts.Tests.csproj]
/w/contracts/UnifiedSmartWallet.csproj : error NU1102:   - Found 35 version(s) in nuget.org [ Nearest version: 3.10.1 ] [/w/tests/AbstractAccount.Contracts.Tests/AbstractAccount.Contracts.Tests.csproj]
  Failed to restore /w/contracts/UnifiedSmartWallet.csproj (in 1.06 sec).
/w/tests/AbstractAccount.Contracts.Tests/AbstractAccount.Contracts.Tests.csproj : error NU1102: Unable to find package Neo.SmartContract.Testing with version (>= 3.10.2-CI00384)
/w/tests/AbstractAccount.Contracts.Tests/AbstractAccount.Contracts.Tests.csproj : error NU1102:   - Found 6 version(s) in nuget.org [ Nearest version: 3.10.1 ]
/w/tests/AbstractAccount.Contracts.Tests/AbstractAccount.Contracts.Tests.csproj : error NU1102: Unable to find package Neo.SmartContract.Framework with version (>= 3.10.2-CI00384)
  Failed to restore /w/tests/AbstractAccount.Contracts.Tests/AbstractAccount.Contracts.Tests.csproj (in 7.79 sec).
`;

function librariesFromManifest(overrides = {}) {
  const libraries = {};
  for (const pkg of manifest.packages) libraries[`${pkg.id}/${pkg.version}`] = { sha512: pkg.sha512, type: "package" };
  return { ...libraries, ...overrides };
}

test("the pins in Directory.Build.props, the tests project and the audited manifest agree", () => {
  const propsVersion = readPinnedVersion(read(PATHS.props), PATHS.props);
  const testsVersion = readPinnedVersion(read(PATHS.testsProject), PATHS.testsProject);
  assert.deepEqual(pinConsistencyProblems({ propsVersion, testsVersion, manifest }), []);
});

test("the manifest lists the framework, the test engine and its private Neo core closure", () => {
  const ids = manifest.packages.map((pkg) => pkg.id).sort();
  assert.deepEqual(ids, [
    "Neo",
    "Neo.Disassembler.CSharp",
    "Neo.Extensions",
    "Neo.IO",
    "Neo.Json",
    "Neo.SmartContract.Framework",
    "Neo.SmartContract.Testing",
    "Neo.VM",
  ]);
});

test("pin drift between the props file, the tests project and the manifest is reported", () => {
  const problems = pinConsistencyProblems({ propsVersion: "3.10.2-CI00385", testsVersion: "3.10.2-CI00384", manifest });
  assert.equal(problems.length, 4);
  assert.match(problems[0], /AbstractAccount\.Contracts\.Tests\.csproj pins 3\.10\.2-CI00384 but .*Directory\.Build\.props pins 3\.10\.2-CI00385/);
  assert.match(problems[1], /neo-platform-packages\.json records 3\.10\.2-CI00384/);
});

test("a clean runner's NU1102 output is recognised as the private packages being unavailable", () => {
  const missing = unavailablePrivatePackages(CLEAN_RUNNER_RESTORE, manifest);
  assert.deepEqual(
    missing.map((pkg) => `${pkg.code} ${pkg.id} ${pkg.range}`),
    ["NU1102 Neo.SmartContract.Framework >= 3.10.2-CI00384", "NU1102 Neo.SmartContract.Testing >= 3.10.2-CI00384"],
  );
});

test("a feed that carries only part of the closure is reported by the missing package", () => {
  const output = [
    "/w/t.csproj : error NU1102: Unable to find package Neo with version (>= 3.10.1.1) [/w/t.csproj]",
    "/w/t.csproj : error NU1101: Unable to find package Neo.Disassembler.CSharp. No packages exist with this id in source(s): nuget.org",
  ].join("\n");
  assert.deepEqual(
    unavailablePrivatePackages(output, manifest).map((pkg) => `${pkg.code} ${pkg.id}`),
    ["NU1102 Neo", "NU1101 Neo.Disassembler.CSharp"],
  );
});

test("restore failures that do not involve the private packages are not blamed on them", () => {
  const output = [
    "/w/t.csproj : error NU1301: Unable to load the service index for source https://feed.invalid/index.json.",
    "/w/t.csproj : error NU1102: Unable to find package MSTest.TestAdapter with version (>= 99.0.0)",
  ].join("\n");
  assert.deepEqual(unavailablePrivatePackages(output, manifest), []);
});

test("the owner-action message names the finding, the reason and every package to publish", () => {
  const message = ownerActionMessage(manifest, unavailablePrivatePackages(CLEAN_RUNNER_RESTORE, manifest));
  assert.match(message, /R-11 \/ N-DEP-1/);
  assert.match(message, /CallWithGasLimit/);
  assert.match(message, /CS0117/);
  assert.match(message, /docs\/NEO-PLATFORM-PACKAGES\.md/);
  assert.match(message, /nuget\.config/);
  for (const pkg of manifest.packages) {
    assert.ok(message.includes(`${pkg.id} ${pkg.version} (sha256 ${pkg.sha256})`), `${pkg.id} missing from message`);
  }
});

test("restored packages with the audited bytes pass", () => {
  assert.deepEqual(restoredPackageProblems(librariesFromManifest(), manifest), []);
});

test("a feed serving different bytes under the pinned version is refused", () => {
  const framework = manifest.packages.find((pkg) => pkg.id === "Neo.SmartContract.Framework");
  const forged = `${"A".repeat(86)}==`;
  const problems = restoredPackageProblems(
    librariesFromManifest({ [`${framework.id}/${framework.version}`]: { sha512: forged, type: "package" } }),
    manifest,
  );
  assert.equal(problems.length, 1);
  assert.match(problems[0], /Neo\.SmartContract\.Framework 3\.10\.2-CI00384 sha512 is A+==, audited /);
});

test("a different version of a pinned package, or a stale manifest entry, is refused", () => {
  const libraries = librariesFromManifest();
  delete libraries["Neo/3.10.1.1"];
  libraries["Neo/3.10.1"] = { sha512: `${"B".repeat(86)}==`, type: "package" };
  delete libraries["Neo.VM/3.10.2-CI00384"];
  const problems = restoredPackageProblems(libraries, manifest);
  assert.deepEqual(problems, [
    "Neo restored as Neo/3.10.1, not the audited 3.10.1.1",
    "Neo.VM 3.10.2-CI00384 is not in the restore graph; the manifest is stale",
  ]);
});

test("CI runs the hygiene tests and then the package gate before any dependency install or build", () => {
  const ci = read(".github/workflows/ci.yml");
  const at = (needle) => {
    const index = ci.indexOf(needle);
    assert.notEqual(index, -1, `ci.yml does not contain ${needle}`);
    return index;
  };
  const gate = at("run: node scripts/check_neo_platform_packages.mjs");
  const hygiene = at("run: node --test scripts/repo_hygiene.test.mjs scripts/check_neo_platform_packages.test.mjs");
  assert.ok(at("actions/setup-dotnet@") < gate, "the gate needs the .NET SDK");
  assert.ok(at("actions/setup-node@") < hygiene, "the tests need Node");
  assert.ok(hygiene < gate, "hygiene tests must not be blocked by the package gate");
  for (const later of ["dotnet tool install -g neo.compiler.csharp", "run: npm ci", "npm run test:e2e:install", "run: ./scripts/verify_repo.sh"]) {
    assert.ok(gate < at(later), `the package gate must run before ${later}`);
  }
});

test("verify_repo.sh runs the package gate before the first contract build", () => {
  const script = read("scripts/verify_repo.sh");
  const gate = script.indexOf("node scripts/check_neo_platform_packages.mjs");
  assert.notEqual(gate, -1);
  assert.ok(gate < script.indexOf("dotnet build contracts/UnifiedSmartWallet.csproj"));
  assert.ok(gate < script.indexOf("dotnet test neo-abstract-account.sln"));
  // Both new suites belong to the contract gate's `node --test` invocation.
  const nodeTest = script.indexOf("node --test scripts/lib/deploy-helpers.test.mjs");
  const format = script.indexOf("dotnet format neo-abstract-account.sln");
  for (const suite of ["scripts/check_neo_platform_packages.test.mjs", "scripts/repo_hygiene.test.mjs"]) {
    const at = script.indexOf(suite, nodeTest);
    assert.ok(nodeTest !== -1 && at > nodeTest && at < format, `${suite} is not in the contract gate's node --test run`);
  }
});
