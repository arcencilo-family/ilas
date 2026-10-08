// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — clerkd: the clerk behind a Unix domain socket.
//
// Newline-delimited JSON. Every request line gets exactly one response line,
// in order. A line longer than MAX_LINE_BYTES is refused and the connection is
// closed (there is no way to find the start of the next request after it). So
// is a line that is not complete LINE_DEADLINE_MS after its first byte: the
// idle timeout alone restarts on every byte, and a peer trickling one byte at
// a time would otherwise hold a connection slot for as long as it liked.
//
// One request per connection at a time: once a line is answered, the next line
// on that connection is not served until the answer has left this process. A
// peer that sends requests and never reads the answers therefore stops being
// served once the socket's own buffers are full, instead of making clerkd
// queue answers in memory; it is closed when it has been idle for
// IDLE_TIMEOUT_MS. A connection whose unsent answer passes MAX_UNSENT_BYTES is
// closed at once.
//
// Connections take turns: one request per turn, round-robin over the
// connections that have a complete line waiting, each turn in its own pass of
// the event loop. A peer that pipelines requests and reads every answer at
// once therefore gets one request served per round, like any other
// connection, and cannot keep clerkd from serving the others or from
// accepting new connections. A peer that ends its side of the connection
// after its last request still gets an answer to every complete line it sent.
//
// Limits that remain: any peer that can connect can still hold up to
// MAX_CONNECTIONS connections by sending a complete line (even an empty one)
// more often than every IDLE_TIMEOUT_MS. The daemon cannot tell peers apart.
//
// Who can connect: the socket is chmod'ed to 0600 (default) or 0660, and its
// directory must not let other users in (mode 0700 by default; 0750/0770 with
// a deployer-chosen group when socket_mode is 0660). With 0600 only the
// clerk's own account can connect. The daemon cannot see who connected; a
// submitter_id is a name the peer presents, nothing more.
// ──────────────────────────────────────────────────────────────────────────────

import { randomBytes } from "crypto";
import { createConnection, createServer } from "net";
import type { Server, Socket } from "net";
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, statSync, unlinkSync } from "fs";
import { dirname, join } from "path";
import { ClerkCore } from "./core";
import type { ClerkConfig } from "./config";
import { loadClerkPrivateKey } from "./keys";
import { decodeRequestLine, MAX_LINE_BYTES, MAX_RESPONSE_BYTES } from "./wire";
import type { ClerkResponse } from "./wire";

/** Connections idle longer than this are closed. */
export const IDLE_TIMEOUT_MS = 30_000;
/** A request line must be complete this long after its first byte, or the connection is closed. */
export const LINE_DEADLINE_MS = 10_000;
export const MAX_CONNECTIONS = 64;
/**
 * A connection whose unsent output passes this many bytes is closed. clerkd
 * keeps at most one unsent answer per connection, and no client reads an
 * answer longer than MAX_RESPONSE_BYTES, so an honest connection never
 * reaches it.
 */
export const MAX_UNSENT_BYTES = MAX_RESPONSE_BYTES;

/** The longest delay setTimeout keeps (2^31 − 1 ms); it turns a longer one into 1 ms. */
const MAX_TIMER_MS = 2_147_483_647;

/** Length of the temporary name clerkd binds before linking it to socket_path. */
const BIND_NAME_BYTES = 9; // "." + 8 hex characters

export class ClerkdStartError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClerkdStartError";
  }
}

export interface RunningClerkd {
  readonly socketPath: string;
  readonly core: ClerkCore;
  /** Stop listening, close connections, remove the socket, close the book. */
  close(): Promise<void>;
}

function octal(mode: number): string {
  return "0" + (mode & 0o777).toString(8).padStart(3, "0");
}

function maxSocketPathBytes(): number {
  // sun_path is 108 bytes on Linux and 104 on the BSDs, including the NUL.
  return process.platform === "linux" ? 107 : 103;
}

/** Is something listening on `path`? Resolves "stale" if nothing answers. */
function probeSocket(path: string): Promise<"alive" | "stale"> {
  return new Promise((resolve, reject) => {
    const s = createConnection(path);
    const timer = setTimeout(() => {
      s.destroy();
      resolve("alive"); // it accepted the path but did not refuse: assume a listener
    }, 1000);
    s.once("connect", () => {
      clearTimeout(timer);
      s.destroy();
      resolve("alive");
    });
    s.once("error", (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      s.destroy();
      if (err.code === "ECONNREFUSED" || err.code === "ENOENT") resolve("stale");
      else reject(new ClerkdStartError(`cannot probe existing socket ${path}: ${err.message}`));
    });
  });
}

function prepareSocketDirectory(socketPath: string, socketMode: number): void {
  const dir = dirname(socketPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = statSync(dir);
  if (!st.isDirectory()) throw new ClerkdStartError(`${dir} is not a directory`);
  // 0600 socket: nobody but the owner may even enter the directory.
  // 0660 socket: the group may; other users may not.
  const forbidden = socketMode === 0o600 ? 0o077 : 0o007;
  if ((st.mode & forbidden) !== 0) {
    throw new ClerkdStartError(
      `socket directory ${dir} has mode ${octal(st.mode)}, which lets ` +
        (socketMode === 0o600 ? "other accounts" : "users outside its group") +
        ` reach the socket path. Use a directory with mode ` +
        (socketMode === 0o600 ? "0700" : "0750 or 0770") +
        `, for example a new subdirectory only the clerk's account can enter.`
    );
  }
}

async function clearStaleSocket(socketPath: string): Promise<void> {
  let st;
  try {
    st = lstatSync(socketPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (!st.isSocket()) {
    throw new ClerkdStartError(`${socketPath} exists and is not a socket; refusing to remove it`);
  }
  if ((await probeSocket(socketPath)) === "alive") {
    throw new ClerkdStartError(`another process is already listening on ${socketPath}`);
  }
  unlinkSync(socketPath);
}

function handleLine(core: ClerkCore, line: Buffer): ClerkResponse {
  // A stopped clerk says so to EVERY line, before validating it: otherwise a
  // probe that validation refuses (clerk ping) would hide the stop.
  if (core.failure !== null) return { ok: false, error: `clerk stopped: ${core.failure}` };
  try {
    const req = decodeRequestLine(line);
    return { ok: true, receipt: core.submit(req) };
  } catch (err) {
    return { ok: false, error: (err as Error).message ?? String(err) };
  }
}

/**
 * Turns for the connections that hold a complete request line: one request
 * per turn, connections served in the order they became ready, and each turn
 * in its own pass of the event loop. A connection with more lines waiting
 * goes to the back of the queue after its turn, so a peer that pipelines
 * requests gets one turn per round like everyone else, and new data and new
 * connections are read between any two requests.
 */
class TurnQueue {
  private readonly ready: Array<() => void> = [];
  private scheduled = false;

  /** `serve` runs once, on a later turn. */
  enqueue(serve: () => void): void {
    this.ready.push(serve);
    this.schedule();
  }

  private schedule(): void {
    if (this.scheduled || this.ready.length === 0) return;
    this.scheduled = true;
    setImmediate(this.turn);
  }

  private readonly turn = (): void => {
    this.scheduled = false;
    const serve = this.ready.shift();
    try {
      if (serve !== undefined) serve();
    } finally {
      this.schedule();
    }
  };
}

function serveConnection(
  socket: Socket,
  handle: (line: Buffer) => ClerkResponse,
  lineDeadlineMs: number,
  turns: TurnQueue
): void {
  /** Bytes received and not yet taken as a request line, in arrival order. */
  let held: Buffer[] = [];
  let heldLen = 0;
  /** `held` contains a newline: a complete request line waits for its turn. */
  let lineReady = false;
  /** This connection is in the turn queue. */
  let queued = false;
  /** An answer has been written and has not yet left this process. */
  let inFlight = false;
  /** The peer has ended its side; the lines already received are still answered. */
  let peerEnded = false;
  let done = false;
  /** Runs while a request line has started and not yet ended. */
  let lineTimer: NodeJS.Timeout | null = null;
  const stopLineTimer = (): void => {
    if (lineTimer !== null) {
      clearTimeout(lineTimer);
      lineTimer = null;
    }
  };
  /** The first byte of a new line starts its clock; later bytes do not reset it. */
  const startLineTimer = (): void => {
    if (lineTimer !== null || heldLen === 0) return;
    lineTimer = setTimeout(
      () => refuseAndClose(`request line not complete within ${lineDeadlineMs} ms of its first byte`),
      lineDeadlineMs
    );
  };
  socket.setTimeout(IDLE_TIMEOUT_MS, () => socket.destroy());
  socket.on("error", () => {
    /* a peer that drops its connection is not a clerk failure */
  });
  socket.on("close", () => {
    done = true;
    stopLineTimer();
    held = [];
    heldLen = 0;
  });

  /** Take the first complete line out of `held` (without its newline). */
  const takeLine = (): Buffer | null => {
    for (let i = 0; i < held.length; i++) {
      const nl = held[i].indexOf(0x0a);
      if (nl === -1) continue;
      const parts = held.slice(0, i);
      parts.push(held[i].subarray(0, nl));
      const line = parts.length === 1 ? parts[0] : Buffer.concat(parts);
      const rest = held[i].subarray(nl + 1);
      held = rest.length > 0 ? [rest, ...held.slice(i + 1)] : held.slice(i + 1);
      heldLen -= line.length + 1;
      lineReady = held.some((b) => b.indexOf(0x0a) !== -1);
      return line;
    }
    return null;
  };

  /** Ask for a turn, and read nothing more on this connection until it has had it. */
  const awaitTurn = (): void => {
    if (queued || inFlight || done) return;
    queued = true;
    socket.pause();
    turns.enqueue(serveOne);
  };

  /** This connection's turn: answer one request line. */
  const serveOne = (): void => {
    queued = false;
    if (done || socket.destroyed || socket.writableEnded) return;
    const line = takeLine();
    if (line === null) return; // cannot happen: a turn is asked for only with a line ready
    if (line.length > MAX_LINE_BYTES) {
      refuseAndClose(`request line longer than ${MAX_LINE_BYTES} bytes`);
      return;
    }
    const answer = JSON.stringify(handle(line)) + "\n";
    if (done || socket.destroyed) return;
    // One request per connection in flight: the next line on this connection
    // waits until this answer has left the process. Otherwise a peer that
    // writes requests and never reads the answers makes clerkd keep every
    // answer in memory.
    inFlight = true;
    socket.write(answer, (err) => {
      inFlight = false;
      if (err) return;
      afterAnswer();
    });
    if (socket.writableLength > MAX_UNSENT_BYTES) {
      // More than any client reads: the connection is of no use any more.
      done = true;
      stopLineTimer();
      socket.destroy();
    }
  };

  /** The last answer has left: the next line gets a turn, or reading goes on. */
  const afterAnswer = (): void => {
    if (done || socket.destroyed) return;
    if (lineReady) {
      awaitTurn();
      return;
    }
    if (peerEnded) {
      finish();
      return;
    }
    startLineTimer(); // a partial line held while this connection waited
    socket.resume();
  };

  /** Every line the peer sent before it ended has been answered: end our side too. */
  const finish = (): void => {
    if (done) return;
    done = true;
    stopLineTimer();
    held = [];
    heldLen = 0;
    socket.end();
  };

  socket.on("data", (chunk: Buffer) => {
    if (done || socket.destroyed) return;
    held.push(chunk);
    heldLen += chunk.length;
    if (!lineReady && chunk.indexOf(0x0a) !== -1) lineReady = true;
    if (lineReady) {
      stopLineTimer();
      awaitTurn();
      return;
    }
    if (heldLen > MAX_LINE_BYTES) {
      refuseAndClose(`request line longer than ${MAX_LINE_BYTES} bytes`);
      return;
    }
    startLineTimer();
  });

  // The server is created with allowHalfOpen, so a peer that sends its last
  // requests and ends its side at once still gets every answer: the lines
  // already received are answered first, and only then is this side ended.
  socket.on("end", () => {
    peerEnded = true;
    if (!queued && !inFlight && !lineReady) finish();
  });

  function refuseAndClose(reason: string): void {
    if (done) return;
    done = true;
    stopLineTimer();
    held = [];
    heldLen = 0;
    const response: ClerkResponse = { ok: false, error: `${reason}; connection closed` };
    socket.end(JSON.stringify(response) + "\n", () => socket.destroy());
    // A peer that does not read cannot keep the half-closed socket open either.
    setTimeout(() => socket.destroy(), 1000).unref();
  }
}

export interface StartClerkdOptions {
  /** Called with one-line status messages (start, warnings). Default: none. */
  log?: (message: string) => void;
  /**
   * How long a request line may take to arrive, from its first byte to its
   * newline. Default LINE_DEADLINE_MS. A line still incomplete then is refused
   * and the connection closed. More than 0 and at most 2147483647 (the
   * longest delay setTimeout keeps); anything else is refused at start.
   */
  lineDeadlineMs?: number;
}

/**
 * Start the daemon from a config: load the key (refusing a key others can
 * read), open and verify the book (refusing a book that does not verify),
 * then listen. Resolves once the socket accepts connections.
 */
export async function startClerkd(
  config: ClerkConfig,
  options: StartClerkdOptions = {}
): Promise<RunningClerkd> {
  const log = options.log ?? (() => undefined);
  const lineDeadlineMs = options.lineDeadlineMs ?? LINE_DEADLINE_MS;
  if (!Number.isFinite(lineDeadlineMs) || lineDeadlineMs <= 0) {
    throw new ClerkdStartError("lineDeadlineMs must be a positive number");
  }
  if (lineDeadlineMs > MAX_TIMER_MS) {
    // setTimeout would replace it with 1 ms, and refuse every line that arrives in two pieces.
    throw new ClerkdStartError(
      `lineDeadlineMs is ${lineDeadlineMs}; a timer runs for at most ${MAX_TIMER_MS} ms (about 24.8 days)`
    );
  }
  const socketPath = config.socketPath;
  if (Buffer.byteLength(socketPath, "utf8") > maxSocketPathBytes()) {
    throw new ClerkdStartError(
      `socket path is ${Buffer.byteLength(socketPath)} bytes; this platform allows ${maxSocketPathBytes()}`
    );
  }
  // clerkd binds a temporary name in the socket's directory first (see below).
  const bindPath = join(dirname(socketPath), "." + randomBytes((BIND_NAME_BYTES - 1) / 2).toString("hex"));
  if (Buffer.byteLength(bindPath, "utf8") > maxSocketPathBytes()) {
    throw new ClerkdStartError(
      `socket directory ${dirname(socketPath)} is too long: clerkd binds a ${BIND_NAME_BYTES}-byte ` +
        `temporary name in it first, and that path would be ${Buffer.byteLength(bindPath)} bytes; ` +
        `this platform allows ${maxSocketPathBytes()}`
    );
  }
  const privateKey = loadClerkPrivateKey(config.privateKeyPath);
  const core = ClerkCore.open({
    clerkId: config.clerkId,
    privateKey,
    bookPath: config.bookPath,
    separation: "SEPARATE_PROCESS",
    allowedSubmitters: config.allowedSubmitters,
    retainPayload: config.retainPayload,
  });
  if (core.bookState === "NEW") {
    log(
      `book ${config.bookPath} is absent or empty: starting at clerk_seq 0. ` +
        `This is either a first run or a removed book; this process cannot tell which.`
    );
  }

  let stopReported = false;
  const handle = (line: Buffer): ClerkResponse => {
    const response = handleLine(core, line);
    if (!stopReported && core.failure !== null) {
      stopReported = true;
      log(`clerk stopped and refuses every request until restarted: ${core.failure}`);
    }
    return response;
  };

  const connections = new Set<Socket>();
  const turns = new TurnQueue();
  // allowHalfOpen: a peer's end does not end this side at once; serveConnection
  // ends it after answering every line the peer sent before its end.
  const server: Server = createServer({ allowHalfOpen: true }, (socket) => {
    connections.add(socket);
    socket.on("close", () => connections.delete(socket));
    serveConnection(socket, handle, lineDeadlineMs, turns);
  });
  server.maxConnections = MAX_CONNECTIONS;
  let socketIno: number;
  try {
    prepareSocketDirectory(socketPath, config.socketMode);
    await clearStaleSocket(socketPath);
    // Bind a temporary name, then hard-link it to socket_path and drop the
    // temporary name. On close, Node (libuv) unlinks the path it bound,
    // whatever is there by then; bound at socket_path, a stopping clerkd would
    // remove a socket another clerkd had since put at that path. Bound at the
    // temporary name, only close() below touches socket_path, and only if it
    // is still this socket. link() also fails rather than replace anything
    // that appeared at socket_path after the stale check.
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(bindPath, () => {
        server.off("error", reject);
        resolve();
      });
    });
    try {
      chmodSync(bindPath, config.socketMode);
      try {
        linkSync(bindPath, socketPath);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") {
          throw new ClerkdStartError(
            `${socketPath} appeared while clerkd was starting; refusing to replace it`
          );
        }
        throw err;
      }
    } finally {
      try {
        unlinkSync(bindPath);
      } catch {
        /* nothing to clean up */
      }
    }
    socketIno = lstatSync(socketPath).ino;
  } catch (err) {
    if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
    core.close();
    throw err;
  }
  server.on("error", (err) => log(`server error: ${err.message}`));

  let closing: Promise<void> | null = null;
  const close = (): Promise<void> => {
    if (closing !== null) return closing;
    closing = new Promise<void>((resolve) => {
      server.close(() => resolve());
      for (const c of connections) c.end();
      const force = setTimeout(() => {
        for (const c of connections) c.destroy();
      }, 1000);
      force.unref();
    }).then(() => {
      try {
        // Remove the socket only if it is still the one this process created.
        if (lstatSync(socketPath).ino === socketIno) unlinkSync(socketPath);
      } catch {
        /* already removed on close */
      }
      core.close();
    });
    return closing;
  };

  return { socketPath, core, close };
}
