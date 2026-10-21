import type { RemoteAccessInfo } from '@/api/types'

/**
 * Which remote-access tabs the device page shows: only for users holding the
 * privilege (admins via `*`), and only when the server reports remote access
 * at all (older servers omit `remote_access`). A tab whose feature is
 * unavailable still shows, with the reason.
 */
export function visibleRemoteTabs(can: (p: string) => boolean, info: RemoteAccessInfo | undefined): { desktop: boolean; files: boolean } {
  if (!info) return { desktop: false, files: false }
  return { desktop: can('remote.desktop'), files: can('remote.files') }
}
