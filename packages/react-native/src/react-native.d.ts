/**
 * The adapter uses the host application's React Native runtime as a peer
 * dependency. This declaration keeps editor/type tooling deterministic when
 * the package is inspected outside a React Native application.
 */
declare const require: (moduleName: string) => unknown;

/** Minimal compile-time seam used when the workspace intentionally does not
 * install a React Native runtime. Published consumers resolve the real peer
 * package and its declarations. */
declare module "react-native" {
  export interface HostComponent<Props = unknown> {
    readonly __secureKeypadProps?: Props;
  }

  export function requireNativeComponent<Props>(name: string): HostComponent<Props>;
}
