import type { CalErrorKind } from "./CalErrorKind";
/**
 * Error wrapping native errors.
 *
 * The native libraries used large lists of errors that might occur.
 * This struct exists to dumm down said errors.
 * The provider implementation should map errors from native libraries to this enum.
 * Most if not all errors should have a source for backtraces.
 * If other fields are usefull for understanding the error, they should also exist.
 */
export type CalError = {
    error_kind: CalErrorKind;
};
//# sourceMappingURL=CalError.d.ts.map