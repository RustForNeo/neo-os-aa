// Reads the repository's own ".gitignore" files and answers the one question
// "git check-ignore" answers: would "git add" exclude this repository-relative
// path?
//
// It exists because a clean "git archive" export has no ".git" directory, so
// "git check-ignore --no-index" cannot run there, and the review service
// mandates a clean archive export. The hygiene test uses git itself whenever a
// work tree is present, and falls back to this module otherwise; the two are
// held together by a cross-check over every path in the tree (see
// "scripts/repo_hygiene.test.mjs", test "the ignore rules read the same in this
// tree and in git").
//
// Supported semantics are git's, deliberately limited to what ".gitignore"
// defines: whole-line comments, blank lines, "!" negation, "\" escaping, a
// trailing "/" for directories, a leading or embedded "/" for anchoring, "*",
// "?", "[...]" character classes and "**". A pattern's own file position is
// fixed by where it was read from, and a pattern without a "/" matches the
// basename at any depth under that directory.
//
// One documented divergence: git resolves a path's rules bottom-up and would
// report a path under an ignored directory as not-ignored when a deeper
// ".gitignore" re-includes it. This walk stops at an ignored directory, which
// is what "git add" does. The cross-check in the hygiene test fails if the two
// disagree anywhere in this repository.

import fs from "node:fs";
import path from "node:path";

/**
 * Splits one ".gitignore" line into a pattern string, or null when the line
 * carries no pattern (blank or comment).
 */
export function parseIgnoreLine(rawLine) {
  let line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
  // A trailing space is not part of the pattern unless it is escaped.
  while (line.endsWith(" ") && !line.endsWith("\\ ")) line = line.slice(0, -1);
  if (line === "") return null;
  if (line.startsWith("#")) return null;
  return line;
}

/**
 * Compiles one ".gitignore" pattern into a matcher over a path that is already
 * relative to the directory holding the ".gitignore" file.
 *
 * `directoryOnly` mirrors git's "the pattern ends with a slash" rule; callers
 * pass whether the path being tested names a directory.
 */
export function compileIgnorePattern(pattern) {
  const directoryOnly = pattern.endsWith("/");
  let body = directoryOnly ? pattern.replace(/\/+$/, "") : pattern;
  if (body === "") return null;

  let negated = false;
  if (body.startsWith("!") && body.length > 1) {
    negated = true;
    body = body.slice(1);
  }

  // A leading slash anchors the pattern and is not part of it.
  const leadingSlash = body.startsWith("/");
  if (leadingSlash) body = body.slice(1);
  if (body === "") return null;

  // A slash anywhere but at the end anchors the pattern to the ".gitignore"
  // file's directory; without one it matches a basename at any depth, which is
  // expressed as an optional leading path.
  const anchored = leadingSlash || body.includes("/");
  const segments = body.split("/");
  // A leading "**/" stands for zero or more leading directories; inside the
  // pattern a lone "**" spans them. Every other segment is a plain glob.
  const rest = segments[0] === "**" && segments.length > 1 ? segments.slice(1) : segments;
  const prefix = anchored ? (segments[0] === "**" && segments.length > 1 ? "(?:.*/)?" : "") : "(?:.*/)?";
  const source = ["(?:"];
  rest.forEach((segment, index) => {
    if (segment === "**") {
      // "a/**/b" matches "a/b" and everything between them; a trailing "**"
      // matches every child of the directory before it, not the directory.
      if (index === 0 && rest.length === 1) source.push(".*");
      else if (index === rest.length - 1) source.push("(?:/[^/]+)*");
      else source.push("(?:/[^/]+)*/");
      return;
    }
    if (index > 0 && rest[index - 1] !== "**") source.push("/");
    source.push(translateSegment(segment));
  });
  source.push(")");

  return {
    directoryOnly,
    negated,
    pattern,
    anchored,
    regex: new RegExp(`^${prefix}${source.join("")}$`),
  };
}

function translateSegment(segment) {
  let out = "";
  for (let index = 0; index < segment.length; index += 1) {
    const character = segment[index];
    if (character === "\\") {
      index += 1;
      out += index < segment.length ? escapeRegExp(segment[index]) : "\\\\";
      continue;
    }
    if (character === "*") {
      out += "[^/]*";
      continue;
    }
    if (character === "?") {
      out += "[^/]";
      continue;
    }
    if (character === "[") {
      const close = segment.indexOf("]", index + 1);
      if (close === -1) {
        out += "\\[";
        continue;
      }
      let body = segment.slice(index + 1, close);
      index = close;
      if (body.startsWith("!")) body = `^${body.slice(1)}`;
      out += `[${body.replace(/[\\^\]]/g, "\\$&")}]`;
      continue;
    }
    out += escapeRegExp(character);
  }
  return out;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Returns every ".gitignore" below `directory`, repository-relative to it. */
export function findIgnoreFiles(directory) {
  const found = [];
  const visit = (relative) => {
    const absolute = path.join(directory, relative);
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      if (entry.isDirectory()) visit(path.join(relative, entry.name));
      else if (entry.name === ".gitignore") found.push(relative);
    }
  };
  visit("");
  return found.sort();
}

/** Compiled patterns of one ".gitignore", shallowest file first. */
function readIgnoreFile(directory, relativeDirectory) {
  if (relativeDirectory !== "" && relativeDirectory !== "." && !directoryExists(directory, relativeDirectory)) {
    return null;
  }
  const file = path.join(directory, relativeDirectory, ".gitignore");
  if (!fs.existsSync(file)) return null;
  const patterns = [];
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const parsed = parseIgnoreLine(line);
    if (parsed === null) continue;
    const compiled = compileIgnorePattern(parsed);
    if (compiled !== null) patterns.push(compiled);
  }
  return patterns;
}

function directoryExists(directory, relative) {
  try {
    return fs.statSync(path.join(directory, relative)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The ignore rules of one exported tree, without git.
 *
 * `directory` is the tree's root. Every answer is relative to it and uses "/"
 * separators, exactly like the paths "git check-ignore" is given.
 */
export function loadIgnoreRules(directory) {
  const cache = new Map();
  const rulesAt = (relativeDirectory) => {
    if (!cache.has(relativeDirectory)) {
      cache.set(relativeDirectory, readIgnoreFile(directory, relativeDirectory) ?? []);
    }
    return cache.get(relativeDirectory);
  };

  // Shallowest directory first: every ".gitignore" is a block of rules that
  // applies from its own directory downwards, and the last matching rule wins.
  const accumulated = (segments, includeLeafDirectory) => {
    const rules = [];
    const depth = segments.length;
    const last = includeLeafDirectory ? depth : depth - 1;
    for (let index = 0; index <= last; index += 1) {
      const relativeDirectory = segments.slice(0, index).join("/");
      for (const rule of rulesAt(relativeDirectory)) {
        rules.push({ relativeDirectory, rule });
      }
    }
    return rules;
  };

  // `depth` is how many leading segments form the path the rule is being
  // applied to, which is not always the whole path: a directory rule is
  // satisfied by naming an ancestor directory, not by naming a descendant of
  // it ("node_modules/" ignores "node_modules/pkg/index.js" by ignoring
  // "node_modules"). A prefix shorter than the whole path always names a
  // directory, so a directory rule applies to it.
  const verdictAt = (rules, segments, depth, leafIsDirectory) => {
    let verdict = false;
    for (const { relativeDirectory, rule } of rules) {
      // A prefix shorter than the whole path always names a directory, so a
      // directory rule applies to it; only the whole path can be a plain file.
      if (rule.directoryOnly && depth === segments.length && !leafIsDirectory) continue;
      const prefix = relativeDirectory === "" ? "" : `${relativeDirectory}/`;
      const relative = segments.slice(0, depth).join("/");
      if (prefix !== "" && !relative.startsWith(prefix)) continue;
      const candidate = prefix === "" ? relative : relative.slice(prefix.length);
      if (rule.regex.test(candidate)) verdict = !rule.negated;
    }
    return verdict;
  };

  return {
    root: directory,
    /** True when "git add" would exclude `relativePath` from `directory`. */
    isIgnored(relativePath, isDirectory = false) {
      const segments = relativePath.split("/").filter((segment) => segment !== "" && segment !== ".");
      if (segments.length === 0) return false;
      // A path under an ignored directory is ignored whatever its own rules
      // say; the walk mirrors the descent "git add" performs and stops there.
      const ancestors = segments.length - 1;
      for (let depth = 1; depth <= ancestors; depth += 1) {
        if (verdictAt(accumulated(segments, depth), segments, depth, true)) return true;
      }
      // The path itself: its own directory's rules apply to it, and to a
      // directory also the rules of the ".gitignore" that directory holds.
      return verdictAt(
        accumulated(segments, isDirectory ? segments.length : segments.length - 1),
        segments,
        segments.length,
        isDirectory,
      );
    },
    /** The subset of `paths` the rules exclude, as a Set. */
    ignoredSet(paths) {
      return new Set(paths.filter((relativePath) => this.isIgnored(relativePath)));
    },
    /** Every ".gitignore" the walk reads, repository-relative. */
    files() {
      return findIgnoreFiles(directory);
    },
  };
}
