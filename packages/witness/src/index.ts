// Reference witness — public surface. See ../README.md.

export {
  receiptPreimage,
  signReceipt,
  verifyReceipt,
  isReceiptShape,
  decodeSignature,
  receiptBytes,
  receiptFileName,
  receiptIndexOf,
  RECEIPT_KEYS,
} from "./receipt";
export type { ReceiptFields, WitnessReceipt } from "./receipt";

export {
  checkHeadCommit,
  bareNameProblem,
  submitterIdProblem,
  MAX_SUBMITTER_ID_BYTES,
  GENESIS_HASH,
  HEAD_COMMIT_KEYS,
} from "./commit";
export type { HeadCommit, CommitCheck } from "./commit";

export {
  parseConfig,
  loadConfigFile,
  comparablePath,
  ConfigError,
  DEFAULT_POLL_INTERVAL_MS,
  MIN_POLL_INTERVAL_MS,
  MAX_POLL_INTERVAL_MS,
} from "./config";
export type { WitnessConfig, SubmitterConfig } from "./config";

export {
  generateKeyFiles,
  loadPrivateKeyFile,
  loadPublicKeyFile,
  publicKeyFingerprint,
  octalMode,
  KeyFileError,
  PRIVATE_KEY_FILE,
  PUBLIC_KEY_FILE,
} from "./keys";
export type { GeneratedKeyFiles } from "./keys";

export {
  readStore,
  recordHash,
  recordLine,
  recordSigPreimage,
  signRecord,
  verifyRecordSig,
  receiptOf,
  SubmitterHistory,
  StoreAppender,
  StoreBroken,
  StoreWriteError,
  RECORD_SIG_DOMAIN,
} from "./store";
export type {
  StoreRecord,
  UnsignedRecord,
  UnhashedRecord,
  ConflictNote,
  StoreContents,
  ReadStoreOptions,
} from "./store";

export {
  ReferenceWitness,
  WitnessRefusal,
  WitnessHalted,
  MAX_INTAKE_BYTES,
  STAGING_DIR,
} from "./witness";
export type { PollEvent, StartupReport, WitnessOptions, RefusalCode } from "./witness";
