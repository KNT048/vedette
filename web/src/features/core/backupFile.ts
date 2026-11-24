/** The file inputs of a restore from a backup file (first run and Settings -> Data). */
export const FILE_INPUT = 'text-sm file:mr-3 file:h-9 file:cursor-pointer file:rounded-md file:border file:border-rule file:bg-surface file:px-3 file:text-sm'
/** The key file is the 32 bytes of vedette.key; anything over 4 KiB is not one and is not read. */
const MAX_KEY_FILE = 4096

/** The key file as base64 for the request, null when it is too large to be one. */
export async function keyBase64(f: File): Promise<string | null> {
  if (f.size > MAX_KEY_FILE) return null
  const b = new Uint8Array(await f.arrayBuffer())
  return btoa(String.fromCharCode(...b))
}
