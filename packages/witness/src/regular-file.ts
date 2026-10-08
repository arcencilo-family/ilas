// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — reading a file an operator names: a key file, the config,
// the store.
//
// The file is opened O_RDONLY|O_NONBLOCK and checked with fstat on that same
// descriptor before anything is read. A FIFO with no writer, which a plain
// open() waits on for ever, is opened at once and refused, as are a directory,
// a socket and a device: a command given one of them exits with a reason
// instead of hanging. O_NONBLOCK changes nothing for a regular file. Where the
// platform has no O_NONBLOCK (Windows) the flag is 0, and there is no FIFO to
// wait on there either.
// ──────────────────────────────────────────────────────────────────────────────

import { closeSync, constants, fstatSync, openSync, readFileSync, statSync } from "fs";
import type { Stats } from "fs";

/** open() flags for a file that is checked with fstat before it is read: never blocks. */
const OPEN_FOR_READING_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);

/** What a file that is not a regular file is, for an error message. */
function fileKind(stats: Stats): string {
  if (stats.isFIFO()) return "a FIFO";
  if (stats.isDirectory()) return "a directory";
  if (stats.isSocket()) return "a socket";
  if (stats.isCharacterDevice()) return "a character device";
  if (stats.isBlockDevice()) return "a block device";
  return "a file of another kind";
}

/** Thrown by readRegularFile() for a path that is there but is not a regular file. */
export class NotARegularFile extends Error {
  constructor(readonly path: string, kind: string) {
    super(`${path} is not a regular file (it is ${kind})`);
    this.name = "NotARegularFile";
  }
}

/** An error from readRegularFile() as the tail of a "cannot read …: " message. */
export function readErrorText(error: unknown): string {
  return error instanceof NotARegularFile ? error.message : String(error);
}

/**
 * A descriptor for the regular file at `path`, opened without blocking; the
 * caller closes it. Throws NotARegularFile for a FIFO, a directory, a socket or
 * a device; any other failure (ENOENT, EACCES, …) is thrown as open() threw it.
 */
export function openRegularFile(path: string): number {
  let fd: number;
  try {
    fd = openSync(path, OPEN_FOR_READING_FLAGS);
  } catch (error) {
    // open() of a UNIX socket fails with ENXIO: say what is there instead.
    if ((error as NodeJS.ErrnoException).code === "ENXIO") {
      let stats: Stats | null = null;
      try {
        stats = statSync(path);
      } catch {
        // gone in between: report the open error
      }
      if (stats !== null && !stats.isFile()) throw new NotARegularFile(path, fileKind(stats));
    }
    throw error;
  }
  let stats: Stats;
  try {
    stats = fstatSync(fd);
  } catch (error) {
    closeSync(fd);
    throw error;
  }
  if (!stats.isFile()) {
    closeSync(fd);
    throw new NotARegularFile(path, fileKind(stats));
  }
  return fd;
}

/** The bytes of the regular file at `path`, read through openRegularFile()'s descriptor. */
export function readRegularFile(path: string): Buffer {
  const fd = openRegularFile(path);
  try {
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}
