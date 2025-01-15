import type { KeyType } from "./KeyType";
/**
 * flutter_rust_bridge:non_opaque
 */
export type CalErrorKind = "NotImplemented" | {
    "BadParameter": {
        description: string;
        /**
         * `true` if caused within this library. `false` if caused by another library.
         */
        internal: boolean;
    };
} | {
    "MissingKey": {
        key_id: string;
        key_type: KeyType;
    };
} | {
    "MissingValue": {
        description: string;
        /**
         * `true` if caused within this library. `false` if caused by another library.
         */
        internal: boolean;
    };
} | {
    "FailedOperation": {
        description: string;
        /**
         * `true` if caused within this library. `false` if caused by another library.
         */
        internal: boolean;
    };
} | {
    "InitializationError": {
        description: string;
        /**
         * `true` if caused within this library. `false` if caused by another library.
         */
        internal: boolean;
    };
} | {
    "UnsupportedAlgorithm": string;
} | "EphermalKeyError" | "Other";
//# sourceMappingURL=CalErrorKind.d.ts.map