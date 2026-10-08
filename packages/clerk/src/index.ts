// Reference clerk for ILAS. See ../README.md.

export {
  RECEIPT_FORM,
  GENESIS_RECEIPT_HASH,
  payloadCommitment,
  receiptPreimage,
  signReceipt,
  verifyReceipt,
} from "./receipt";
export type { ClerkReceipt, UnsignedClerkReceipt, Separation, Intake, Verdict } from "./receipt";

export {
  Book,
  BookChecker,
  BookError,
  BookLockError,
  BookVerificationError,
  BookWriteError,
  MAX_BOOK_LINE_BYTES,
  verifyBookFile,
  verifyBookRecords,
} from "./book";
export type { BookVerdict, BookOpenState } from "./book";

export {
  ClerkKeyError,
  PRIVATE_KEY_FILE,
  PUBLIC_KEY_FILE,
  generateClerkKeyFiles,
  loadClerkPrivateKey,
  loadPublicKeyPem,
  publicKeyPemOf,
} from "./keys";
export type { GeneratedKeyFiles } from "./keys";

export { ClerkCore, ClerkStoppedError, IN_PROCESS_WARNING } from "./core";
export type { ClerkCoreOptions } from "./core";

export {
  ClerkPayloadError,
  ClerkRequestError,
  MAX_LINE_BYTES,
  MAX_NAME_LENGTH,
  MAX_PAYLOAD_BYTES,
  MAX_REQUEST_OVERHEAD_BYTES,
  MAX_RESPONSE_BYTES,
  decodeRequestLine,
  encodeRequest,
  validateRequest,
} from "./wire";
export type { ClerkResponse, SubmitRequest } from "./wire";

export { ClerkConfigError, loadConfigFile, parseConfig } from "./config";
export type { ClerkConfig } from "./config";

export { ClerkdStartError, startClerkd } from "./server";
export type { RunningClerkd, StartClerkdOptions } from "./server";

export { ReconcileError, reconcileBookAndLogs, reconcileFoundNoGaps } from "./reconcile";
export type {
  BookOnlyReceipt,
  LogOnlyEntry,
  LogTally,
  ReconcileOptions,
  ReconcileReport,
} from "./reconcile";

export {
  ClerkRefusedError,
  ClerkTransportError,
  DEFAULT_PING_TIMEOUT_MS,
  DEFAULT_TIMEOUT_MS,
  InProcessClerkClient,
  PING_PROBE,
  SocketClerkClient,
  pingClerkd,
} from "./client";
export type { SocketClerkClientOptions } from "./client";
