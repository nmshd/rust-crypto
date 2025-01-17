// This file was generated by [ts-rs](https://github.com/Aleph-Alpha/ts-rs). Do not edit this file manually.
import type { KeyType } from "./KeyType";

/**
 * Enumeration differentiating between the causes and the severity of the error.
 */
export type CalErrorKind =
  | "NotImplemented"
  | {
    "BadParameter": {
      description: string;
      /**
       * `true` if caused within this library. `false` if caused by another library.
       */
      internal: boolean;
    };
  }
  | { "MissingKey": { key_id: string; key_type: KeyType } }
  | {
    "MissingValue": {
      description: string;
      /**
       * `true` if caused within this library. `false` if caused by another library.
       */
      internal: boolean;
    };
  }
  | {
    "FailedOperation": {
      description: string;
      /**
       * `true` if caused within this library. `false` if caused by another library.
       */
      internal: boolean;
    };
  }
  | {
    "InitializationError": {
      description: string;
      /**
       * `true` if caused within this library. `false` if caused by another library.
       */
      internal: boolean;
    };
  }
  | { "UnsupportedAlgorithm": string }
  | "EphermalKeyError"
  | "Other";
