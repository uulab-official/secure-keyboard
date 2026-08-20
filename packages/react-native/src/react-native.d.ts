/**
 * The adapter uses the host application's React Native runtime as a peer
 * dependency. This declaration keeps editor/type tooling deterministic when
 * the package is inspected outside a React Native application.
 */
declare const require: (moduleName: string) => unknown;
