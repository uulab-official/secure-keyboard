import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";

/**
 * Returns whether an evidence path or any existing parent component is a
 * symbolic link. Evidence files are hashed and later reviewed as immutable
 * release inputs, so following even an in-root symlink would make that
 * contract dependent on mutable filesystem resolution.
 *
 * @param {string} root
 * @param {string} absolutePath
 * @returns {boolean}
 */
export function pathHasSymlinkComponent(root, absolutePath) {
  const realRoot = realpathSync(root);
  let cursor = path.resolve(absolutePath);
  while (cursor !== realRoot && cursor.startsWith(`${realRoot}${path.sep}`)) {
    try {
      if (lstatSync(cursor).isSymbolicLink()) return true;
    } catch {
      // The caller performs the regular-file/existence check after this scan.
    }
    cursor = path.dirname(cursor);
  }
  return false;
}
