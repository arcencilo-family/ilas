// ──────────────────────────────────────────────────────────────────────────────
// ILAS — independence fence: the core reaches nothing outside src/ except Node's
// own built-in modules.
//
// The reference clerk and witness live in packages/. They may import ILAS's wire
// helpers; ILAS must never import them. If it did, "run the witness somewhere
// else" would stop being true of the code, whatever the docs say. The core also
// uses Node built-ins only, so no npm package may be imported either.
//   npx ts-node src/fence.test.ts
//
// WHAT THIS IS. A static check that stops ACCIDENTAL dependencies: an import
// added without noticing where it leads, a helper copied in with its require(),
// a loader reached out of habit. It reads the source; it does not run it. It is
// NOT a sandbox against deliberate evasion: code written to hide a load from it
// can do so (see WHAT IT CANNOT SEE), and reading the diff is the defence
// against that.
//
// HOW IT IS CHECKED. Every file under src/ must be a .ts file: its name ends
// in ".ts", lower case. Anything else is refused unread: Node loads a file of
// another name (x.js, x.TS, plain x) as JavaScript when pointed at it, a
// .node file is native code, and a package.json can send a directory import
// outside src/ through its "main". A symbolic link anywhere under src/ is refused: its target is not
// checked. Each .ts file is parsed with the TypeScript compiler API
// (ts.createSourceFile) and its syntax tree is walked. A file that does not
// parse cleanly is refused: it cannot be checked exactly. Comments and string
// contents are not code and are not checked.
//
// WHAT IS A MODULE REFERENCE: an import declaration (import type included); an
// export ... from declaration (export type included); an import-equals
// declaration (import x = require("...")); a type-level import("..."); a
// dynamic import(); a require() call, where the callee is require however it
// is spelled (the parser resolves unicode escapes), called optionally
// (require?.(...)), parenthesised, or reached as a member named require
// (module.require(...)); a require.resolve() call; and a triple-slash path
// reference (and a triple-slash types reference written as a path).
//
// THE RULES. A test file is a *.test.ts file. Every other file, fixtures
// included, is a runtime file.
//   1. The specifier must be ONE string literal or template literal with no
//      substitution. Anything else (a concatenation, a method called on a
//      literal, a substitution, a spread, a cast or parenthesised literal)
//      cannot be checked and is refused. require() and require.resolve() take
//      exactly one argument; import() takes the specifier and at most an
//      options object.
//   2. The specifier is judged by its COOKED text, escapes resolved, which is
//      what the runtime resolves. A relative specifier must resolve inside
//      src/. An absolute one is refused, even inside src/: it ties the code to
//      one checkout. A bare one must be a Node built-in (a "node:" prefix is
//      allowed), except that a runtime file may not name the "module"
//      built-in: it is Node's loader. The one exception the other way: a test
//      file may also import the package's devDependencies (this file needs
//      "typescript"). Runtime files import Node built-ins and src/ only.
//   3. require reached in any way other than a direct call (kept in a
//      variable, passed along, destructured under another name, bound, named
//      by import x = require.cache) is refused: the alias would load modules
//      unchecked. typeof require loads nothing and is allowed. require.main is
//      allowed in a test file only: its constructor is the loader.
//   4. Node's loader internals are refused by name, in every file, wherever
//      they appear as an identifier or a literal member name: createRequire,
//      _load, _resolveFilename, _compile, _extensions, dlopen, mainModule
//      (process.mainModule, whose constructor is the loader) and
//      getBuiltinModule (it hands out any built-in, the module built-in too,
//      past rule 2).
//   5. In a runtime file the module object is refused except as module.exports
//      (and typeof module): module.require, module.constructor, module.parent
//      and the object itself all reach the loader.
//   6. arguments where no ordinary function encloses it is refused, in every
//      file: at the top level it is the CommonJS wrapper's, whose second and
//      third entries are require and module.
//
// WHAT IT CANNOT SEE, deliberate evasion first among it: a name built at run
// time (m["_lo" + "ad"], or one handed to Reflect.get or
// Object.getOwnPropertyDescriptor), eval, new Function, the vm module, and a
// module loaded by a child process or a worker thread. Test files are held
// to less: they may use require.main, the module object and the module
// built-in. `tsc --noEmit` (rootDir: src) is the second line for static
// imports; it follows a .d.ts, not what Node loads.
//
// This file is scanned too. Its planted cases are strings, and string contents
// are not code, so it holds none of the forms it plants.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "fs";
import { builtinModules } from "module";
import { tmpdir } from "os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "path";
import * as ts from "typescript";

let passed = 0;
let failed = 0;
function check(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${(err as Error).message}`);
    failed++;
  }
}

const SRC = resolve(__dirname);
const BUILTINS = new Set<string>(builtinModules);
const DEV_DEPENDENCIES = new Set<string>(
  Object.keys(
    (JSON.parse(readFileSync(join(SRC, "..", "package.json"), "utf8")) as {
      devDependencies?: Record<string, string>;
    }).devDependencies ?? {}
  )
);
const LOADER_NAME = "require";
const MODULE_NAME = "module";
const LOADER_INTERNALS = new Set([
  "createRequire",
  "_load",
  "_resolveFilename",
  "_compile",
  "_extensions",
  "dlopen",
  "mainModule",
  "getBuiltinModule",
]);

// ── the checker ───────────────────────────────────────────────────────────────

interface Walk {
  readonly files: string[];
  readonly symlinks: string[];
}

function vanished(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

/** Every regular file and every symbolic link under `dir`; links are not followed. */
function walk(dir: string, out: Walk = { files: [], symlinks: [] }): Walk {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    let st;
    try {
      st = lstatSync(p);
    } catch (error) {
      if (vanished(error)) continue; // removed since it was listed: nothing to import
      throw error;
    }
    if (st.isSymbolicLink()) out.symlinks.push(p);
    else if (st.isDirectory()) walk(p, out);
    else if (st.isFile()) out.files.push(p);
  }
  return out;
}

function inside(root: string, target: string): boolean {
  return target === root || target.startsWith(root + sep);
}

/** "pkg" for "pkg/sub", "@scope/pkg" for "@scope/pkg/sub". */
function packageName(spec: string): string {
  const parts = spec.split("/");
  return spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

/** Why `spec` (cooked), written in `file`, leaves `root` — or null when it does not. */
function specifierProblem(root: string, file: string, spec: string, testFile: boolean): string | null {
  if (spec === "." || spec === ".." || spec.startsWith("./") || spec.startsWith("../")) {
    return inside(root, resolve(dirname(file), spec)) ? null : "relative path outside src/";
  }
  if (isAbsolute(spec)) return "absolute path";
  const name = spec.startsWith("node:") ? spec.slice("node:".length) : spec;
  if (!testFile && name === MODULE_NAME) return "the module built-in is Node's loader; not in a runtime file";
  if (BUILTINS.has(name)) return null;
  if (testFile && name === spec && DEV_DEPENDENCIES.has(packageName(spec))) return null;
  return testFile ? "neither a Node built-in nor a devDependency" : "not a Node built-in";
}

/** Why a triple-slash path `ref` in `file` leaves `root`, or null. */
function pathReferenceProblem(root: string, file: string, ref: string): string | null {
  if (isAbsolute(ref)) return "absolute path";
  return inside(root, resolve(dirname(file), ref)) ? null : "path outside src/";
}

function stripParentheses(node: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(node)) node = node.expression;
  return node;
}

/** The cooked text of a string literal (or of ["literal"]), else null. */
function stringText(node: ts.Node | undefined): string | null {
  if (node === undefined) return null;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isComputedPropertyName(node)) return stringText(node.expression);
  return null;
}

/** The name a member access reads (x.name, x?.name, x["name"]), when it is written out. */
function memberName(node: ts.Node): string | null {
  if (ts.isPropertyAccessExpression(node)) {
    return ts.isIdentifier(node.name) ? ts.idText(node.name) : null;
  }
  if (ts.isElementAccessExpression(node)) return stringText(node.argumentExpression);
  return null;
}

/** require itself, or a member named require (module.require, m["require"]). */
function isLoaderReference(node: ts.Expression): boolean {
  return (
    (ts.isIdentifier(node) && ts.idText(node) === LOADER_NAME) ||
    memberName(node) === LOADER_NAME
  );
}

/**
 * True when `id` is not a use of a binding's value: a type (typeof x in a type,
 * a type name), or the name a declaration or a key gives (a parameter, a
 * variable, a key). A shorthand property and an export specifier USE the
 * binding they name, and so does a dotted name in import x = a.b, which is a
 * value alias at run time, not a type.
 */
function nameOrType(id: ts.Identifier): boolean {
  const p = id.parent;
  if (ts.isTypeQueryNode(p) || ts.isTypeReferenceNode(p)) return true;
  if (ts.isQualifiedName(p)) {
    let top: ts.Node = p;
    while (ts.isQualifiedName(top.parent)) top = top.parent;
    return !ts.isImportEqualsDeclaration(top.parent);
  }
  const named = (p as { name?: ts.Node }).name === id;
  return named && !ts.isShorthandPropertyAssignment(p) && !ts.isExportSpecifier(p);
}

/**
 * True when the identifier `require` at `id` reaches the loader as a value that
 * nothing checks. `checked` holds the callees of checked calls.
 */
function loaderUsedAsValue(id: ts.Identifier, checked: ReadonlySet<ts.Node>): boolean {
  if (checked.has(id)) return false; // require(...), require.resolve(...)
  const p = id.parent;
  if (ts.isPropertyAccessExpression(p)) {
    if (p.name === id) return !checked.has(p); // module.require: fine only as a checked call
    return memberName(p) !== "main"; // require.main: judged by requireMain()
  }
  if (ts.isTypeOfExpression(p)) return false; // typeof require: loads nothing
  // A declaration whose own name is require (a parameter, a variable, a key):
  // calls through that name are checked like calls to the real one.
  return !nameOrType(id);
}

/** True when the identifier `require` at `id` is the object of require.main. */
function requireMain(id: ts.Identifier): boolean {
  const p = id.parent;
  return ts.isPropertyAccessExpression(p) && p.expression === id && memberName(p) === "main";
}

/**
 * True when the identifier `module` at `id` is the module object used for
 * anything but module.exports (or typeof module): its require, constructor and
 * parent, and the object itself, reach the loader.
 */
function moduleUsedAsValue(id: ts.Identifier): boolean {
  const p = id.parent;
  if (ts.isPropertyAccessExpression(p) || ts.isElementAccessExpression(p)) {
    if (p.expression === id) return memberName(p) !== "exports"; // module.exports, module["exports"]
    return ts.isElementAccessExpression(p); // x[module] uses it; x.module is a member name
  }
  if (ts.isTypeOfExpression(p)) return false;
  return !nameOrType(id);
}

/**
 * True when `arguments` at `id` is the CommonJS wrapper's (exports, require,
 * module, ...): no ordinary function encloses it. An arrow function has no
 * arguments of its own, and a method's computed name and decorators are
 * evaluated outside it.
 */
function wrapperArguments(id: ts.Identifier): boolean {
  const p = id.parent;
  if (ts.isPropertyAccessExpression(p) && p.name === id) return false; // x.arguments
  if (nameOrType(id)) return false;
  let child: ts.Node = id;
  for (let n: ts.Node = p; !ts.isSourceFile(n); child = n, n = n.parent) {
    if (
      ts.isFunctionLike(n) &&
      !ts.isArrowFunction(n) &&
      (n as ts.SignatureDeclaration).name !== child &&
      !ts.isDecorator(child)
    ) {
      return false;
    }
  }
  return true;
}

interface FileScan {
  readonly specifiers: string[];
  readonly offenders: string[];
}

/** The specifiers `source` (the text of `file`, under `root`) names, and what is wrong. */
function scanSource(root: string, file: string, source: string): FileScan {
  const where = relative(root, file);
  const specifiers: string[] = [];
  const offenders: string[] = [];
  if (!file.endsWith(".ts")) {
    return {
      specifiers,
      offenders: [
        `${where}: not a .ts file (Node can load it as code, and a package.json can ` +
          `send a directory import outside src/); refused unread`,
      ],
    };
  }

  const testFile = file.endsWith(".test.ts");
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const lineOf = (pos: number) => sf.getLineAndCharacterOfPosition(pos).line + 1;
  const flag = (node: ts.Node, what: string) => offenders.push(`${where}:${lineOf(node.getStart(sf))}: ${what}`);

  // Internal to the compiler, so read defensively: without it nothing is checked.
  const parseErrors = (sf as unknown as { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics;
  if (parseErrors === undefined) {
    offenders.push(`${where}: this TypeScript exposes no parse diagnostics; the file cannot be checked`);
  } else if (parseErrors.length > 0) {
    const first = parseErrors[0];
    offenders.push(
      `${where}:${lineOf(first.start ?? 0)}: does not parse cleanly ` +
        `(${ts.flattenDiagnosticMessageText(first.messageText, " ")}); it cannot be checked`
    );
  }

  for (const ref of sf.referencedFiles) {
    const problem = pathReferenceProblem(root, file, ref.fileName);
    if (problem !== null) {
      offenders.push(`${where}:${lineOf(ref.pos)}: ${JSON.stringify(ref.fileName)} in a triple-slash path reference (${problem})`);
    }
  }
  for (const ref of sf.typeReferenceDirectives) {
    if (!ref.fileName.startsWith(".") && !isAbsolute(ref.fileName)) continue; // a package's types
    const problem = pathReferenceProblem(root, file, ref.fileName);
    if (problem !== null) {
      offenders.push(`${where}:${lineOf(ref.pos)}: ${JSON.stringify(ref.fileName)} in a triple-slash types reference (${problem})`);
    }
  }

  const specifier = (arg: ts.Node | undefined, form: string, at: ts.Node) => {
    if (arg === undefined) {
      flag(at, `${form} with no specifier`);
      return;
    }
    if (!ts.isStringLiteral(arg) && !ts.isNoSubstitutionTemplateLiteral(arg)) {
      flag(arg, `computed specifier in ${form} (not one string literal; cannot be checked)`);
      return;
    }
    specifiers.push(arg.text);
    const problem = specifierProblem(root, file, arg.text, testFile);
    if (problem !== null) flag(arg, `${JSON.stringify(arg.text)} in ${form} (${problem})`);
  };

  // Loader references that are the callee of a checked call. Filled in before
  // the walk reaches them: a call is visited before its children.
  const checkedCallees = new Set<ts.Node>();

  const visitCall = (call: ts.CallExpression) => {
    if (call.expression.kind === ts.SyntaxKind.ImportKeyword) {
      if (call.arguments.length > 2) flag(call, "a dynamic import() with more than a specifier and options");
      specifier(call.arguments[0], "a dynamic import()", call);
      return;
    }
    const callee = stripParentheses(call.expression);
    let form: string | null = null;
    if (isLoaderReference(callee)) {
      checkedCallees.add(callee);
      form = "a require() call";
    } else if (
      (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) &&
      memberName(callee) === "resolve" &&
      isLoaderReference(stripParentheses(callee.expression))
    ) {
      checkedCallees.add(stripParentheses(callee.expression));
      form = "a require.resolve() call";
    }
    if (form === null) return;
    if (call.arguments.length > 1) flag(call, `${form} with more than one argument`);
    specifier(call.arguments[0], form, call);
  };

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      const typeOnly = node.importClause?.isTypeOnly === true;
      specifier(node.moduleSpecifier, typeOnly ? "an import type declaration" : "an import declaration", node);
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) {
      specifier(node.moduleSpecifier, "an export-from declaration", node);
    } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      specifier(node.moduleReference.expression, "an import-equals declaration", node);
    } else if (ts.isImportTypeNode(node)) {
      const arg = node.argument;
      specifier(ts.isLiteralTypeNode(arg) ? arg.literal : arg, "a type-level import()", node);
    } else if (ts.isCallExpression(node)) {
      visitCall(node);
    }

    // A name, however written: an identifier anywhere (a property access's name
    // is one), or a literal member name (x["n"], { "n": local } = x).
    const name = ts.isIdentifier(node)
      ? ts.idText(node)
      : ts.isElementAccessExpression(node)
        ? stringText(node.argumentExpression)
        : ts.isBindingElement(node)
          ? stringText(node.propertyName)
          : null;
    if (name !== null && LOADER_INTERNALS.has(name)) flag(node, `${name} (a loader internal)`);
    if (
      name === LOADER_NAME &&
      (ts.isIdentifier(node) ? loaderUsedAsValue(node, checkedCallees) : !checkedCallees.has(node))
    ) {
      flag(node, "require used other than as a direct call (an alias loads unchecked)");
    }
    if (ts.isIdentifier(node)) {
      if (!testFile && name === LOADER_NAME && requireMain(node)) {
        flag(node, "require.main (its constructor is Node's loader; not in a runtime file)");
      }
      if (!testFile && name === MODULE_NAME && moduleUsedAsValue(node)) {
        flag(
          node,
          "module other than module.exports (its require, constructor and parent reach " +
            "Node's loader; not in a runtime file)"
        );
      }
      if (name === "arguments" && wrapperArguments(node)) {
        flag(
          node,
          "arguments where no function encloses it (at the top level it is the CommonJS " +
            "wrapper's: exports, require, module)"
        );
      }
    }

    ts.forEachChild(node, visit);
  };
  visit(sf);
  return { specifiers, offenders };
}

interface TreeScan extends Walk {
  readonly specifiers: Set<string>;
  readonly offenders: string[];
}

function scanTree(root: string): TreeScan {
  const tree = walk(root);
  const specifiers = new Set<string>();
  const offenders: string[] = tree.symlinks.map(
    (p) => `${relative(root, p)}: symbolic link under src/ (its target is not checked)`
  );
  for (const file of tree.files) {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch (error) {
      if (vanished(error)) continue;
      throw error;
    }
    const scan = scanSource(root, file, text);
    scan.specifiers.forEach((s) => specifiers.add(s));
    offenders.push(...scan.offenders);
  }
  return { ...tree, specifiers, offenders };
}

// ── planted controls ──────────────────────────────────────────────────────────

const BSL = "\\"; // one backslash, so the escape forms below read plainly
const up = "../..";
const PK = `${up}/packages/witness/src/keys`;
const ABS_OUTSIDE = resolve(SRC, "..", "packages", "clerk", "src", "client");
const ABS_INSIDE = join(SRC, "l0", "index");

const OUTSIDE = "outside src/";
const COMPUTED = "computed specifier";
const NOT_BUILTIN = "not a Node built-in";
const ALIAS = "an alias loads unchecked";
const INTERNAL = "a loader internal";
const NOT_TS = "not a .ts file";
const MODULE_BUILTIN = "the module built-in is Node's loader";
const MODULE_OBJECT = "module other than module.exports";
const REQUIRE_MAIN = "require.main (its constructor is Node's loader";
const WRAPPER_ARGUMENTS = "arguments where no function encloses it";

/**
 * [label, file it is planted in (under src/), source, the reason it must be
 * flagged for]. Each must be flagged FOR THAT REASON, so that a row cannot pass
 * on some other finding (a parse error, say) while its own form slips through.
 */
const ESCAPES: ReadonlyArray<readonly [string, string, string, string]> = [
  // declarations
  ["static import statement", "l0/p.ts", `import { C } from "${up}/packages/clerk/src/client";`, OUTSIDE],
  ["side-effect import statement", "l0/p.ts", `import "${up}/packages/clerk/src/side-effect";`, OUTSIDE],
  ["import type declaration", "l0/p.ts", `import type { C } from "${up}/packages/clerk/src/client";`, OUTSIDE],
  ["re-export of names", "l0/p.ts", `export { C } from "${up}/packages/clerk/src/client";`, OUTSIDE],
  ["re-export of a type", "l0/p.ts", `export type { C } from "${up}/packages/clerk/src/client";`, OUTSIDE],
  ["re-export of everything", "l0/p.ts", `export * from '${PK}';`, OUTSIDE],
  ["multi-line re-export", "l0/p.ts", `export {\n  C,\n  D,\n} from\n  "${up}/packages/x";`, OUTSIDE],
  ["import-equals declaration", "l0/p.ts", `import k = require("${PK}");`, OUTSIDE],
  ["exported import-equals declaration", "l0/p.ts", `export import k = require("${PK}");`, OUTSIDE],
  ["type-level import()", "l0/p.ts", `type K = typeof import("${PK}");`, OUTSIDE],
  // calls with a literal
  ["require of a literal", "l0/p.ts", `const w = require("${up}/packages/witness/src/witness");`, OUTSIDE],
  ["require nested in a class method's arrow", "l0/p.ts", `class A { m() { return () => require("${PK}"); } }`, OUTSIDE],
  ["dynamic import, double quotes", "l0/p.ts", `const d = import("${up}/packages/clerk/src/client");`, OUTSIDE],
  ["dynamic import, single quotes", "l0/p.ts", `const d = import('${up}/packages/clerk/src/client');`, OUTSIDE],
  ["dynamic import, plain template", "l0/p.ts", `const d = import(\`${up}/packages/clerk/src/client\`);`, OUTSIDE],
  ["dynamic import, comment before the paren", "l0/p.ts", `const d = import /* c */ ("${up}/packages/x");`, OUTSIDE],
  ["'./..' style relative path", "l0/p.ts", `const w = require("./${up}/packages/witness/src/witness");`, OUTSIDE],
  ["sibling directory sharing the src prefix", "p.ts", `import "../src-x/evil";`, OUTSIDE],
  ["the resolve method of the require function", "l0/p.ts", `const p = require.resolve("${PK}");`, OUTSIDE],
  ["an optional resolve", "l0/p.ts", `const p = require?.resolve("${PK}");`, OUTSIDE],
  ["module.require", "l0/p.ts", `const k = module.require("${PK}");`, OUTSIDE],
  ["require as a literal member name", "l0/p.ts", `const k = module["require"]("${PK}");`, OUTSIDE],
  ["a parenthesised callee", "l0/p.ts", `const k = (require)("${PK}");`, OUTSIDE],
  // the escape forms: the literal is judged by its cooked text
  ["hex escapes in the literal", "l0/p.ts", `const k = require("./${BSL}x2e${BSL}x2e/${BSL}x2e${BSL}x2e/packages/witness/src/keys");`, OUTSIDE],
  ["identity escapes in the literal", "l0/p.ts", `const k = require("./.${BSL}./..${BSL}/packages/witness/src/keys");`, OUTSIDE],
  ["a line continuation in the literal", "l0/p.ts", `const k = require("./.${BSL}\n./../packages/witness/src/keys");`, OUTSIDE],
  ["unicode escapes in the literal", "l0/p.ts", `const k = require("${BSL}u002e${BSL}u{2e}/../packages/witness/src/keys");`, OUTSIDE],
  ["an escape in a plain template", "l0/p.ts", `const k = import(\`${BSL}x2e./../packages/witness/src/keys\`);`, OUTSIDE],
  ["a unicode escape spelling the keyword", "l0/p.ts", `const c = ${BSL}u0072equire("${up}/packages/witness/src/commit");`, OUTSIDE],
  ["a braced unicode escape spelling the keyword", "l0/p.ts", `const c = ${BSL}u{72}equire("${up}/packages/witness/src/commit");`, OUTSIDE],
  ["an optional call", "l0/p.ts", `const s = require?.("${up}/packages/witness/src/store");`, OUTSIDE],
  // specifiers that are not one literal
  ["a method called on the literal", "l0/p.ts", `const r = require("crypto".replace("crypto", "${up}/packages/witness/src/receipt"));`, COMPUTED],
  ["a literal that starts a concatenation", "l0/p.ts", `const k = require("." + "./../packages/clerk/src/keys");`, COMPUTED],
  ["a literal prefix plus a variable", "l0/p.ts", `const k = require("./plugins/" + name);`, COMPUTED],
  ["require of an expression", "l0/p.ts", `const w = require(up + "/packages/witness/src/receipt");`, COMPUTED],
  ["require of a template with a substitution", "l0/p.ts", `const w = require(\`\${base}/x\`);`, COMPUTED],
  ["dynamic import, template with substitution", "l0/p.ts", `const d = import(\`\${base}/packages/clerk\`);`, COMPUTED],
  ["dynamic import of an expression", "l0/p.ts", `const d = import(base + "/packages/x");`, COMPUTED],
  ["a parenthesised literal", "l0/p.ts", `const d = require(("crypto"));`, COMPUTED],
  ["a cast literal", "l0/p.ts", `const d = require("crypto" as string);`, COMPUTED],
  ["a spread argument", "l0/p.ts", `const d = require(...parts);`, COMPUTED],
  ["import-equals of a non-literal", "l0/p.ts", `import k = require(name);`, COMPUTED],
  ["require with no argument", "l0/p.ts", `const d = require();`, "with no specifier"],
  ["require with a second argument", "l0/p.ts", `const d = require("crypto", x);`, "more than one argument"],
  // where the specifier leads
  ["absolute path outside src/", "l0/p.ts", `import { C } from "${ABS_OUTSIDE}";`, "absolute path"],
  ["absolute path inside src/", "l0/p.ts", `import { L } from "${ABS_INSIDE}";`, "absolute path"],
  ["bare npm package", "l0/p.ts", `import express from "express";`, NOT_BUILTIN],
  ["scoped npm package", "l0/p.ts", `const s = require("@scope/pkg");`, NOT_BUILTIN],
  ["a devDependency in a runtime file", "l0/p.ts", `import * as ts from "typescript";`, NOT_BUILTIN],
  ["a devDependency in a fixture", "s4/x.fixture.ts", `import "ts-node/register";`, NOT_BUILTIN],
  ["a non-dependency in a test file", "l0/p.test.ts", `import express from "express";`, "nor a devDependency"],
  ["a devDependency behind node:", "l0/p.test.ts", `import "node:typescript";`, "nor a devDependency"],
  ["file: URL", "l0/p.ts", `const d = import("file:///etc/passwd");`, NOT_BUILTIN],
  ["a backslash-relative path", "l0/p.ts", `const d = require("..${BSL}${BSL}..${BSL}${BSL}packages");`, NOT_BUILTIN],
  // require reached as a value
  ["require kept in a variable", "l0/p.ts", `const r = require; r("${PK}");`, ALIAS],
  ["require behind the comma operator", "l0/p.ts", `const k = (0, require)("${PK}");`, ALIAS],
  ["require passed as an argument", "l0/p.ts", `load(require);`, ALIAS],
  ["require bound", "l0/p.ts", `const r = require.bind(null);`, ALIAS],
  ["require in a shorthand property", "l0/p.ts", `const o = { require };`, ALIAS],
  ["module.require as a value", "l0/p.ts", `const r = module.require;`, ALIAS],
  ["require destructured under another name", "l0/p.ts", `const { require: r } = module;`, ALIAS],
  ["require destructured by a literal name", "l0/p.ts", `const { "require": r } = module;`, ALIAS],
  ["require.cache", "l0/p.ts", `delete require.cache[k];`, ALIAS],
  ["a non-null asserted callee", "l0/p.ts", `const k = require!("crypto");`, ALIAS],
  ["a member of require named by import-equals", "l0/p.ts", `import c = require.cache;`, ALIAS],
  // the loader itself, which runtime files may not touch
  ["the module built-in", "l0/p.ts", `import Module from "module"; new (Module as any)("x").load("${PK}.ts");`, MODULE_BUILTIN],
  ["the module built-in behind node:", "l0/p.ts", `const M = require("node:module");`, MODULE_BUILTIN],
  ["the module built-in in a fixture", "s4/x.fixture.ts", `import { builtinModules } from "module";`, MODULE_BUILTIN],
  ["the module object's constructor", "l0/p.ts", `const M = module.constructor as any; new M("x").load("${PK}.ts");`, MODULE_OBJECT],
  ["module.require in a runtime file, even of a built-in", "l0/p.ts", `const os = module.require("os");`, MODULE_OBJECT],
  ["the module object's prototype", "l0/p.ts", `const P = Object.getPrototypeOf(module);`, MODULE_OBJECT],
  ["the module object's parent", "l0/p.ts", `const p = module.parent;`, MODULE_OBJECT],
  ["the module object kept in a variable", "l0/p.ts", `const m = module;`, MODULE_OBJECT],
  ["the module object in a shorthand property", "l0/p.ts", `const o = { module };`, MODULE_OBJECT],
  ["the module object's constructor by import-equals", "l0/p.ts", `import M = module.constructor;`, MODULE_OBJECT],
  ["require.main in a runtime file", "l0/p.ts", `const M = require.main!.constructor;`, REQUIRE_MAIN],
  ["require.main in a fixture", "s4/x.fixture.ts", `if (require.main) run();`, REQUIRE_MAIN],
  ["the CommonJS wrapper's arguments at the top level", "l0/p.ts", `const load = arguments[1];`, WRAPPER_ARGUMENTS],
  ["the wrapper's arguments in a top-level arrow", "l0/p.ts", `const f = () => arguments[2];`, WRAPPER_ARGUMENTS],
  ["the wrapper's arguments in a method's computed name", "l0/p.ts", `class A { [arguments[1]("os")]() {} }`, WRAPPER_ARGUMENTS],
  ["the wrapper's arguments in a test file", "l0/p.test.ts", `const load = arguments[1];`, WRAPPER_ARGUMENTS],
  // loader internals
  ["a require factory from the module built-in", "l0/p.ts", `import { createRequire } from "module";`, INTERNAL],
  ["Module._load reached through require of module", "l0/p.ts", `(require("module") as any)._load("${PK}", module);`, INTERNAL],
  ["Module._resolveFilename", "l0/p.ts", `const p = M._resolveFilename("x", module);`, INTERNAL],
  ["a loader internal as a literal member name", "l0/p.ts", `const l = M["_load"];`, INTERNAL],
  ["a loader internal destructured", "l0/p.ts", `const { _compile: c } = m;`, INTERNAL],
  ["process.dlopen", "l0/p.ts", `process.dlopen(m, "/tmp/x.node");`, INTERNAL],
  ["Module._extensions", "l0/p.ts", `(M as any)._extensions[".ts"](m, "${PK}.ts");`, INTERNAL],
  ["process.mainModule", "l0/p.ts", `const M = process.mainModule!.constructor;`, INTERNAL],
  ["process.mainModule in a test file", "l0/p.test.ts", `const M = process.mainModule;`, INTERNAL],
  ["process.getBuiltinModule", "l0/p.ts", `const M = process.getBuiltinModule("module");`, INTERNAL],
  // files that are not .ts are refused unread, whatever they hold
  ["a package.json whose main leaves src/", "l0/shim/package.json", `{ "types": "./index.d.ts", "main": "${up}/../packages/clerk/src/wire.ts" }`, NOT_TS],
  ["a JSON file", "l0/p.json", `{ "a": 1 }`, NOT_TS],
  ["a .js file", "l0/p.js", `module.exports = 1;`, NOT_TS],
  ["a file with no extension", "l0/p", `module.exports = 1;`, NOT_TS],
  ["a .ts name in another case (Node loads it as JavaScript)", "l0/p.TS", `export {};`, NOT_TS],
  ["a .mts file", "l0/p.mts", `export {};`, NOT_TS],
  ["a native addon", "l0/p.node", "\x7fELF", NOT_TS],
  // triple-slash references
  ["a triple-slash path reference outside src/", "l0/p.ts", `/// <reference path="${PK}.ts" />\nexport {};`, "triple-slash path reference (path outside src/)"],
  ["an absolute triple-slash path reference", "l0/p.ts", `/// <reference path="/etc/x.ts" />\nexport {};`, "triple-slash path reference (absolute path)"],
  ["a triple-slash types reference written as a path", "l0/p.ts", `/// <reference types="${up}/packages/witness" />\nexport {};`, "triple-slash types reference"],
  // the file itself
  ["a file that does not parse", "l0/p.ts", `const a = (;`, "does not parse cleanly"],
];

/** [label, file, source]. Each must pass. */
const ALLOWED: ReadonlyArray<readonly [string, string, string]> = [
  ["a Node built-in", "l0/p.ts", `import { createHash } from "crypto";`],
  ["a Node built-in with the node: prefix", "l0/p.ts", `import "node:fs";`],
  ["a built-in subpath", "l0/p.ts", `const f = require("fs/promises");`],
  ["a sibling module", "l0/p.ts", `import { ok } from "./canonical";`],
  ["the parent barrel, type only", "l0/p.ts", `import type { LogEntry } from "../types";`],
  ["an import-equals of a built-in", "s4/x.fixture.ts", `import fs = require("fs");`],
  ["a dynamic import of a sibling", "s4/p.ts", `const d = import("./witness");`],
  ["a dynamic import with options", "s4/p.ts", `const d = import("./witness", { with: {} });`],
  ["a comment between the literal and the paren", "l0/p.ts", `const c = require("crypto" /* c */);`],
  ["an escape that stays inside src/", "s4/p.ts", `const d = import("${BSL}x2e/witness");`],
  ["require.resolve of a built-in", "l0/p.ts", `const p = require.resolve("crypto");`],
  ["typeof require and typeof module", "l0/p.ts", `if (typeof require === "function" && typeof module === "object") run();`],
  ["module.exports", "l0/p.ts", `module.exports = { a: 1 }; module["exports"].b = 2;`],
  ["a member, a key and a type named module", "l0/p.ts", `const o = { module: 1 }; void o.module; type T = typeof module;`],
  ["require.main and the module object in a test file", "l0/p.test.ts", `if (require.main === module) run(); const M = module.constructor;`],
  ["the module built-in in a test file", "l0/p.test.ts", `import { builtinModules } from "module";`],
  ["arguments inside a function", "l0/p.ts", `function f() { return () => arguments[0]; } const g = function () { return arguments.length; }; class A { m() { return arguments; } }`],
  ["a member and a key named arguments", "l0/p.ts", `const o = { arguments: 1 }; void o.arguments;`],
  ["require and module in a type position", "l0/p.ts", `type C = typeof require.cache; let m: typeof module.constructor;`],
  ["a parameter named require, called with a built-in", "l0/p.ts", `function f(require: (s: string) => unknown) { return require("os"); }`],
  ["a key named require", "l0/p.ts", `const o = { require: true } as const; void o;`],
  ["a test file importing a devDependency", "l0/p.test.ts", `import * as ts from "typescript"; import "ts-node/register";`],
  ["prose and strings are not code", "l0/p.ts", `// taken from "${PK}"; import x from "${PK}"\nconst s = 'require("${PK}") _load ✓';`],
  ["a triple-slash path reference inside src/", "l0/p.ts", `/// <reference path="../types.ts" />\n/// <reference types="node" />\nexport {};`],
  ["a declaration file", "l0/p.d.ts", `export declare const X: number;`],
];

console.log("── The core reaches nothing outside src/ but Node built-ins ──");

check("every planted escape form is flagged, each for its own reason", () => {
  const missed = ESCAPES.filter(([, at, source, reason]) => {
    const { offenders } = scanSource(SRC, join(SRC, at), source);
    return !offenders.some((o) => o.includes(reason));
  }).map(([label, at, source, reason]) => {
    const got = scanSource(SRC, join(SRC, at), source).offenders;
    return `${label} (wanted "${reason}", got ${JSON.stringify(got)})`;
  });
  assert.deepEqual(missed, [], `not flagged: ${missed.join("; ")}`);
});

check("allowed forms are not flagged", () => {
  const flagged = ALLOWED.flatMap(([label, at, source]) =>
    scanSource(SRC, join(SRC, at), source).offenders.map((o) => `${label}: ${o}`)
  );
  assert.deepEqual(flagged, [], flagged.join("; "));
});

check("the walk flags a symlink and every file that is not .ts, unread", () => {
  const root = mkdtempSync(join(tmpdir(), "ilas-fence-"));
  try {
    mkdirSync(join(root, "l0"));
    mkdirSync(join(root, "l0", "shimdir"));
    const shim = `module.exports = require("${PK}");\n`;
    writeFileSync(join(root, "l0", "real.ts"), `import { createHash } from "crypto";\n`);
    writeFileSync(join(root, "l0", "data.json"), `{ "a": 1 }\n`);
    writeFileSync(join(root, "l0", "shim.js"), shim);
    writeFileSync(join(root, "l0", "shim"), shim); // loadable without an extension
    writeFileSync(join(root, "l0", "addon.node"), "\x7fELF");
    // import "./shimdir" would load whatever "main" names, here outside src/
    writeFileSync(join(root, "l0", "shimdir", "package.json"), `{ "main": "${up}/../packages/clerk/src/wire.ts" }\n`);
    symlinkSync(join(up, "packages", "witness", "src", "keys.ts"), join(root, "l0", "wkeys.ts"));

    const scan = scanTree(root);
    const native = (p: string) => p.split("/").join(sep);
    assert.deepEqual(
      scan.files.map((f) => relative(root, f)).sort(),
      ["l0/addon.node", "l0/data.json", "l0/real.ts", "l0/shim", "l0/shim.js", "l0/shimdir/package.json"].map(native)
    );
    const offending = new Set(scan.offenders.map((o) => o.split(":")[0]));
    for (const p of ["l0/addon.node", "l0/data.json", "l0/shim", "l0/shim.js", "l0/shimdir/package.json", "l0/wkeys.ts"]) {
      assert.ok(offending.has(native(p)), `${p} is flagged: ${scan.offenders.join("; ")}`);
    }
    assert.ok(!offending.has(native("l0/real.ts")), "the clean .ts file is not flagged");
    assert.ok(scan.specifiers.has("crypto"), "the .ts file was parsed");
    assert.ok(!scan.specifiers.has(PK), "the files that are not .ts were refused unread");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

let realScan: TreeScan | null = null;
/** The scan of the real tree, made once, inside a check so a failure is reported. */
function realTree(): TreeScan {
  realScan ??= scanTree(SRC);
  return realScan;
}

check("positive control: the real-tree scan parses the real, nested tree", () => {
  const real = realTree();
  for (const known of [
    join(SRC, "l0", "index.ts"),
    join(SRC, "s4", "continuity.ts"),
    join(SRC, "fence.test.ts"),
  ]) {
    assert.ok(real.files.includes(known), `the walk visits ${relative(SRC, known)}`);
  }
  assert.ok(real.files.length >= 30, `only ${real.files.length} files were scanned`);
  assert.ok(real.specifiers.has("crypto"), "the known import of crypto is seen");
  assert.ok(real.specifiers.has("./types"), "a known relative import is seen");
  assert.ok(real.specifiers.has("typescript"), "this file's own import of typescript is seen");
});

check("no file under src/ reaches outside src/ or past Node built-ins", () => {
  const { offenders } = realTree();
  assert.deepEqual(offenders, [], `core escapes src/: ${offenders.join("; ")}`);
});

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
