// This module is the CJS entry point for the library.

// The Rust addon.
export * from './load.cjs';

export * from "./types/index";

// Use this declaration to assign types to the addon's exports,
// which otherwise by default are `any`.
declare module "./load.cjs" {
  export function hello(): string;
  export function getAllProviders(): string[];
}

