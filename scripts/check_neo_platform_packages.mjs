#!/usr/bin/env node

// Fail-fast gate for the private Neo platform packages (audit finding R-11 /
// N-DEP-1).
//
// UnifiedSmartWallet calls Contract.CallWithGasLimit, which only the private
// Neo.SmartContract.Framework build pinned in contracts/Directory.Build.props
// declares, and the contract tests need the matching private TestEngine and Neo
// core. Those packages are on no public feed, so a clean runner fails restore
// with NU1102 deep inside verify_repo.sh. This gate restores them first and, on
// failure, prints the owner action instead of a bare NuGet error. Once they are
// restorable it also refuses packages whose bytes differ from the audited ones
// recorded in contracts/neo-platform-packages.json.
//
// Usage: node scripts/check_neo_platform_packages.mjs

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const PATHS = {
  props: "contracts/Directory.Build.props",
  testsProject: "tests/AbstractAccount.Contracts.Tests/AbstractAccount.Contracts.Tests.csproj",
  coreAssets: "contracts/obj/project.assets.json",
  testsAssets: "tests/AbstractAccount.Contracts.Tests/obj/project.assets.json",
  manifest: "contracts/neo-platform-packages.json",
  doc: "docs/NEO-PLATFORM-PACKAGES.md",
};

/** Reads the default NeoSmartContractFrameworkVersion declared in an MSBuild file. */
export function readPinnedVersion(xml, file) {
  const match = /<NeoSmartContractFrameworkVersion\b[^>]*>\s*([^<\s]+)\s*<\/NeoSmartContractFrameworkVersion>/.exec(xml);
  if (!match) throw new Error(`${file} does not declare NeoSmartContractFrameworkVersion`);
  return match[1];
}

/** Validates the manifest shape and returns it. */
export function parseManifest(text, file = PATHS.manifest) {
  const manifest = JSON.parse(text);
  if (typeof manifest.frameworkVersion !== "string" || !Array.isArray(manifest.packages) || manifest.packages.length === 0) {
    throw new Error(`${file} must declare frameworkVersion and a non-empty packages list`);
  }
  const seen = new Set();
  for (const entry of manifest.packages) {
    for (const field of ["id", "version", "sha512", "sha256"]) {
      if (typeof entry[field] !== "string" || entry[field].length === 0) {
        throw new Error(`${file}: every package needs a non-empty ${field}`);
      }
    }
    if (!/^[A-Za-z0-9+/]{86}==$/.test(entry.sha512)) throw new Error(`${file}: ${entry.id} sha512 must be base64 SHA-512`);
    if (!/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error(`${file}: ${entry.id} sha256 must be lowercase hex SHA-256`);
    const key = entry.id.toLowerCase();
    if (seen.has(key)) throw new Error(`${file}: ${entry.id} is listed twice`);
    seen.add(key);
  }
  return manifest;
}

/** Returns human-readable problems when the pins and the audited manifest disagree. */
export function pinConsistencyProblems({ propsVersion, testsVersion, manifest }) {
  const problems = [];
  if (testsVersion !== propsVersion) {
    problems.push(`${PATHS.testsProject} pins ${testsVersion} but ${PATHS.props} pins ${propsVersion}`);
  }
  if (manifest.frameworkVersion !== propsVersion) {
    problems.push(`${PATHS.manifest} records ${manifest.frameworkVersion} but ${PATHS.props} pins ${propsVersion}`);
  }
  for (const id of ["Neo.SmartContract.Framework", "Neo.SmartContract.Testing"]) {
    const entry = manifest.packages.find((pkg) => pkg.id === id);
    if (!entry) problems.push(`${PATHS.manifest} does not list ${id}`);
    else if (entry.version !== propsVersion) problems.push(`${PATHS.manifest} lists ${id} ${entry.version}, expected ${propsVersion}`);
  }
  return problems;
}

/**
 * Extracts the manifest packages that NuGet could not find (NU1101, NU1102,
 * NU1103) from `dotnet restore` output produced with DOTNET_CLI_UI_LANGUAGE=en.
 */
export function unavailablePrivatePackages(restoreOutput, manifest) {
  const privateIds = new Map(manifest.packages.map((pkg) => [pkg.id.toLowerCase(), pkg.id]));
  const pattern = /error (NU110[123]): Unable to find (?:a stable )?package ([A-Za-z0-9_.-]+?)(?:\.|,)?(?: with version \(([^)]*)\))?(?:\s|$)/g;
  const found = new Map();
  for (const match of restoreOutput.matchAll(pattern)) {
    const id = privateIds.get(match[2].toLowerCase());
    if (!id) continue;
    const range = match[3] ? ` ${match[3]}` : "";
    found.set(`${id}${range}`, { code: match[1], id, range: match[3] ?? null });
  }
  return [...found.values()];
}

/** Compares the libraries NuGet restored against the audited manifest. */
export function restoredPackageProblems(libraries, manifest) {
  const keys = Object.keys(libraries);
  const problems = [];
  for (const pkg of manifest.packages) {
    const wanted = `${pkg.id}/${pkg.version}`.toLowerCase();
    const key = keys.find((candidate) => candidate.toLowerCase() === wanted);
    const restored = key ? libraries[key] : undefined;
    if (!restored) {
      const other = keys.filter((candidate) => candidate.toLowerCase().startsWith(`${pkg.id.toLowerCase()}/`));
      problems.push(
        other.length > 0
          ? `${pkg.id} restored as ${other.join(", ")}, not the audited ${pkg.version}`
          : `${pkg.id} ${pkg.version} is not in the restore graph; the manifest is stale`,
      );
    } else if (restored.sha512 !== pkg.sha512) {
      problems.push(`${pkg.id} ${pkg.version} sha512 is ${restored.sha512}, audited ${pkg.sha512}`);
    }
  }
  return problems;
}

export function ownerActionMessage(manifest, missing) {
  const pinned = manifest.frameworkVersion;
  const listed = manifest.packages.map((pkg) => `     - ${pkg.id} ${pkg.version} (sha256 ${pkg.sha256})`).join("\n");
  const reported = missing.map((pkg) => `${pkg.id}${pkg.range ? ` ${pkg.range}` : ""} [${pkg.code}]`).join(", ");
  return [
    `Neo platform packages unavailable: ${reported}.`,
    "",
    `This is audit finding R-11 / N-DEP-1, not a code defect. contracts/Directory.Build.props pins`,
    `Neo.SmartContract.Framework ${pinned} because UnifiedSmartWallet calls Contract.CallWithGasLimit,`,
    `which no public framework declares: every public release (nuget.org tops out at 3.10.1) fails`,
    `with CS0117, so repinning is not a fix and removing the call would drop the verifier gas cap.`,
    "",
    "Owner action (details, evidence and the nuget.config template: " + PATHS.doc + "):",
    "  1. Publish these packages, byte-for-byte, to a feed this runner can read:",
    listed,
    "  2. Add a repository nuget.config that maps exactly those package ids to that feed.",
    "",
    "Until then the contract build, the contract tests and the deploy-tool tests cannot run on a clean runner.",
  ].join("\n");
}

function readAssetsLibraries(relativePath) {
  const file = path.join(repoRoot, relativePath);
  if (!fs.existsSync(file)) return {};
  return JSON.parse(fs.readFileSync(file, "utf8")).libraries ?? {};
}

function report(title, message) {
  if (process.env.GITHUB_ACTIONS === "true") {
    const encoded = message.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    console.log(`::error title=${title}::${encoded}`);
  }
  console.error(`${title}\n\n${message}`);
}

function main() {
  const read = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
  const manifest = parseManifest(read(PATHS.manifest));
  const propsVersion = readPinnedVersion(read(PATHS.props), PATHS.props);
  const testsVersion = readPinnedVersion(read(PATHS.testsProject), PATHS.testsProject);

  const drift = pinConsistencyProblems({ propsVersion, testsVersion, manifest });
  if (drift.length > 0) {
    report("Neo platform package pins disagree", drift.join("\n"));
    return 1;
  }

  const restore = spawnSync("dotnet", ["restore", PATHS.testsProject, "-nologo"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, DOTNET_CLI_UI_LANGUAGE: "en" },
  });
  if (restore.error) {
    report("dotnet is not available", `Could not run dotnet restore: ${restore.error.message}`);
    return 1;
  }
  const output = `${restore.stdout ?? ""}${restore.stderr ?? ""}`;
  if (restore.status !== 0) {
    const missing = unavailablePrivatePackages(output, manifest);
    if (missing.length > 0) report("Neo platform packages unavailable (R-11)", ownerActionMessage(manifest, missing));
    else report("dotnet restore failed", output.trim().split("\n").slice(-40).join("\n"));
    return 1;
  }

  if (!fs.existsSync(path.join(repoRoot, PATHS.testsAssets))) {
    report("dotnet restore produced no assets file", `${PATHS.testsAssets} is missing after a successful restore.`);
    return 1;
  }
  const libraries = { ...readAssetsLibraries(PATHS.coreAssets), ...readAssetsLibraries(PATHS.testsAssets) };
  const problems = restoredPackageProblems(libraries, manifest);
  if (problems.length > 0) {
    report(
      "Neo platform packages differ from the audited bytes",
      `${problems.join("\n")}\n\nA feed served packages that do not match ${PATHS.manifest}. Do not proceed; see ${PATHS.doc}.`,
    );
    return 1;
  }

  console.log(
    `Neo platform packages OK: ${manifest.packages.length} pinned packages for framework ${propsVersion} restored with the audited sha512.`,
  );
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
