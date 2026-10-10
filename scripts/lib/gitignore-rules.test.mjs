// Pins the semantics of scripts/lib/gitignore-rules.mjs, the no-git reader the
// hygiene test falls back to in a clean "git archive" export.
//
// The hygiene test proves the fallback agrees with "git check-ignore" over the
// repository's own rules. This file proves the reader implements the rules
// ".gitignore" defines, with a fixture whose expected answers are written down
// by hand and, when git is available, checked against git itself in a
// throwaway repository. A reader that answered "ignored" for everything, or
// "not ignored" for everything, fails here before it can weaken the hygiene
// gate.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { compileIgnorePattern, loadIgnoreRules, parseIgnoreLine } from "./gitignore-rules.mjs";

// Each entry is [path, isDirectory, ignored]. The fixture repository below
// writes the ".gitignore" files these answers come from.
const FIXTURE_RULES = [
  ["node_modules/pkg/index.js", false, true],
  ["frontend/node_modules/pkg/index.js", false, true],
  ["sdk/js/dist/index.js", false, true],
  ["dist/index.js", false, true],
  ["anchored/only.js", false, true],
  ["nested/anchored/only.js", false, false],
  // A pattern whose slash is not leading is anchored to the ".gitignore"'s
  // directory too: "/root-only/" names the root copy, not "nested/root-only/".
  ["root-only/here.txt", false, true],
  ["nested/root-only/here.txt", false, false],
  ["build.out", false, true],
  ["keep/build.out", false, false],
  [".env", false, true],
  ["deploy/.env_prod", false, true],
  ["frontend/.env.production.local", false, true],
  [".env.example", false, false],
  ["frontend/.env.example", false, false],
  ["contracts/bin/v3/UnifiedSmartWallet.nef", false, true],
  ["Graph/Graph.csproj", false, false],
  ["bin/Graph.csproj", false, true],
  ["Graph/keep.csproj", false, false],
  [".codegraph/codegraph.db", false, true],
  [".codegraph/daemon.pid", false, true],
  [".codegraph/.gitignore", false, false],
  [".codegraph/nested/deep.json", false, true],
  ["tools/.codegraph/codegraph.db", false, true],
  ["logs/run.txt", false, true],
  ["logs/keep.txt", false, true],
  ["logs/secret.txt", false, true],
  ["a/**/b/target.txt", false, true],
  ["a/b/target.txt", false, true],
  ["a/x/y/b/target.txt", false, true],
  ["b/target.txt", false, false],
  ["file?.txt", false, true],
  ["file1.txt", false, true],
  ["file12.txt", false, false],
  ["class/a.txt", false, true],
  ["class/b.txt", false, true],
  ["class/c.txt", false, false],
  ["escaped[1].txt", false, true],
  ["name with space.txt", false, true],
  ["dir-only", true, true],
  ["dir-only/child.txt", false, true],
  // A directory whose own ".gitignore" negates a parent rule: git still does
  // not descend here, so the file below stays ignored.
  ["!trap", false, false],
  ["trap/keep.txt", false, true],
  ["local/child/.gitignore", false, false],
  ["local/child/tmp/cache.bin", false, true],
  ["local/child/keep.bin", false, false],
];

const FIXTURE_IGNORE_FILES = {
  ".gitignore": [
    "# a comment",
    "",
    "node_modules/",
    "/anchored/",
    "/root-only/",
    "dist/",
    "*.out",
    "!keep/build.out",
    ".env*",
    "!.env.example",
    "bin/",
    "!Graph/keep.csproj",
    "logs/",
    "!logs/keep.txt",
    "**/.codegraph/*",
    "!**/.codegraph/.gitignore",
    "a/**/b/",
    "file?.txt",
    "class/[ab].txt",
    "escaped\\[1\\].txt",
    "name with space.txt   ",
    "dir-only/",
    "!trap",
    "trap/",
  ].join("\n"),
  // The repository's own CodeGraph rule: the database is ignored at every
  // depth, the tracked self-ignoring file is not.
  ".codegraph/.gitignore": ["*", "!.gitignore"].join("\n"),
  "local/child/.gitignore": ["tmp/", "!keep.bin"].join("\n"),
};

// Every compared path is materialised as a file so git can be asked about it:
// the reader does not require a path to exist, git does. A path whose last
// segment is listed here is created as a directory instead.
const FIXTURE_DIRECTORIES = ["dir-only", ".codegraph", "logs", "trap", "local/child/tmp"];
const FIXTURE_FILES = [
  ".gitignore",
  "logs/keep.txt",
  "logs/secret.txt",
  ".codegraph/.gitignore",
  ".codegraph/codegraph.db",
  "local/child/.gitignore",
  "local/child/keep.bin",
  "bin/Graph.csproj",
  "Graph/Graph.csproj",
  "Graph/keep.csproj",
];

function writeFixtureRepository(location) {
  for (const [relative, content] of Object.entries(FIXTURE_IGNORE_FILES)) {
    const file = path.join(location, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `${content}\n`);
  }
  for (const [relative] of FIXTURE_RULES) {
    if (FIXTURE_DIRECTORIES.includes(relative)) continue;
    const file = path.join(location, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (!fs.existsSync(file)) fs.writeFileSync(file, "x\n");
  }
  for (const relative of FIXTURE_DIRECTORIES) {
    fs.mkdirSync(path.join(location, relative), { recursive: true });
  }
}

function gitAvailable() {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** git's own answers for a batch of paths inside a real repository. */
function gitIgnoredSet(repository, paths) {
  try {
    const output = execFileSync(
      "git",
      ["-C", repository, "-c", "core.excludesFile=/dev/null", "check-ignore", "--no-index", "--stdin"],
      { encoding: "utf8", input: `${paths.join("\n")}\n`, stdio: ["pipe", "pipe", "ignore"] },
    );
    return new Set(output.split("\n").filter(Boolean));
  } catch (error) {
    if (error.status === 1) return new Set();
    throw error;
  }
}

test("a pattern line is read the way git reads it", () => {
  assert.equal(parseIgnoreLine("# comment"), null, "a whole-line comment carries no pattern");
  assert.equal(parseIgnoreLine("   # not a comment"), "   # not a comment", "a comment needs its # in column one");
  assert.equal(parseIgnoreLine(""), null, "a blank line carries no pattern");
  assert.equal(parseIgnoreLine("node_modules/"), "node_modules/");
  assert.equal(parseIgnoreLine("name with space.txt   "), "name with space.txt", "trailing spaces are not part of the pattern");
  assert.equal(parseIgnoreLine("name with one escaped\\ "), "name with one escaped\\ ", "an escaped trailing space is part of the pattern");

  assert.equal(compileIgnorePattern("!").negated, false, "a lone ! is an ordinary character");
  assert.equal(compileIgnorePattern("!").regex.test("!"), true);
  assert.equal(compileIgnorePattern("dist/").directoryOnly, true);
  assert.equal(compileIgnorePattern("/dist/").directoryOnly, true);
  assert.equal(compileIgnorePattern("a/b").anchored, true);
  assert.equal(compileIgnorePattern("b").anchored, false);
});

test("the fixture rules read the same in the reader and in git", () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "gitignore-rules-"));
  try {
    writeFixtureRepository(fixture);
    const rules = loadIgnoreRules(fixture);

    const reader = new Map();
    for (const [relative, isDirectory] of FIXTURE_RULES) {
      reader.set(relative, rules.isIgnored(relative, isDirectory));
    }
    for (const [relative, , expected] of FIXTURE_RULES) {
      assert.equal(reader.get(relative), expected, `${relative} should be ${expected ? "ignored" : "not ignored"}`);
    }

    if (!gitAvailable()) return;
    // Only paths that exist can be asked of git; the rest are pinned above.
    execFileSync("git", ["-C", fixture, "init", "-q"], { stdio: "ignore" });
    const compared = FIXTURE_RULES.filter(([relative]) => fs.existsSync(path.join(fixture, relative)));
    assert.ok(
      compared.length >= FIXTURE_RULES.length - 1,
      `the fixture must compare nearly every path with git, compared ${compared.length} of ${FIXTURE_RULES.length}`,
    );
    const gitSays = gitIgnoredSet(fixture, compared.map(([relative]) => relative));
    const disagreements = compared
      .filter(([relative]) => gitSays.has(relative) !== reader.get(relative))
      .map(([relative]) => `${relative}: reader ${reader.get(relative)}, git ${gitSays.has(relative)}`);
    assert.deepEqual(disagreements, [], `the reader and git disagree:\n  ${disagreements.join("\n  ")}`);

    // The hand-written answers must agree with git too, or the fixture is
    // pinning the reader's mistakes.
    const wrongExpectations = compared
      .filter(([relative, , expected]) => gitSays.has(relative) !== expected)
      .map(([relative, , expected]) => `${relative}: expected ${expected}, git says ${gitSays.has(relative)}`);
    assert.deepEqual(wrongExpectations, [], `the fixture's own expectations disagree with git:\n  ${wrongExpectations.join("\n  ")}`);
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

test("a rule that matches nothing cannot silently pass", () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "gitignore-rules-empty-"));
  try {
    fs.writeFileSync(path.join(fixture, ".gitignore"), "nothing-matches-this\n");
    const rules = loadIgnoreRules(fixture);
    assert.equal(rules.isIgnored("node_modules/pkg/index.js"), false, "an unrelated rule ignores nothing");
    assert.equal(rules.isIgnored("nothing-matches-this"), true, "the rule it does name still matches");
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});
