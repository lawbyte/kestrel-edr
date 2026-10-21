import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowUp,
  ArrowDown,
  ChevronRight,
  Download,
  File as FileIcon,
  Folder,
  FolderPlus,
  HardDrive,
  Link2,
  Loader2,
  Lock,
  MoreHorizontal,
  Monitor,
  Pencil,
  RefreshCw,
  Trash2,
  Upload,
  X,
  CheckCircle2,
  AlertCircle,
  Hourglass,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type DragEvent, type KeyboardEvent } from 'react'
import { downloadFile, MFA_NOT_ENABLED_TEXT, mfaNotEnabled, remoteApi, remoteErrorText, remoteKeys, uploadFile, type FmContext, type UploadHandle } from '@/api/remote'
import { MfaSetupLink } from '@/components/mfa-link'
import type { FileEntry, RemoteAccessProfile, RemoteAvailability } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, Label } from '@/components/ui/input'
import { Dropdown, DropdownContent, DropdownItem, DropdownSeparator, DropdownTrigger, Tooltip } from '@/components/ui/misc'
import { formatBytes, formatDateTime } from '@/lib/format'
import { blockedPrefix, consentTimeout, fileOpDenied } from '@/lib/remote-profile'
import { fileNameOf, joinPath, parentOf, pathSegments, sortEntries, validateName, validateRemotePath, type SortKey } from '@/lib/remote-path'
import { cn } from '@/lib/utils'
import { RemoteUnavailable } from './availability'
import { useReauth } from './reauth'

interface UploadItem {
  id: number
  name: string
  target: string
  loaded: number
  total: number
  status: 'queued' | 'uploading' | 'done' | 'failed'
  error?: string
  sha256?: string
  handle?: UploadHandle
  /** Replaces an existing file of the same name. */
  replaces?: boolean
}

type Notice = { kind: 'ok' | 'error'; text: string } | null

const KIND_LABEL: Record<FileEntry['kind'], string> = { file: 'File', dir: 'Folder', drive: 'Drive', link: 'Link' }

export function FileManager({ deviceId, hostname, availability, policyId, effective }: { deviceId: string; hostname: string; availability: RemoteAvailability; policyId: string | null; effective: RemoteAccessProfile }) {
  const qc = useQueryClient()
  const { withReauth } = useReauth()
  // One file-manager session per tab mount: consent is granted per fm_session.
  const [fmSession] = useState(() => crypto.randomUUID())
  const [reason, setReason] = useState('')
  const [reasonSet, setReasonSet] = useState(false)
  const [path, setPath] = useState('')
  const [editing, setEditing] = useState(false)
  const [pathInput, setPathInput] = useState('')
  const [pathError, setPathError] = useState<string | null>(null)
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: 'name', desc: false })
  const [selected, setSelected] = useState<string | null>(null)
  const [dialog, setDialog] = useState<{ kind: 'mkdir' } | { kind: 'rename'; entry: FileEntry } | null>(null)
  const [notice, setNotice] = useState<Notice>(null)
  const [busy, setBusy] = useState<Record<string, string>>({})
  const [uploads, setUploads] = useState<UploadItem[]>([])
  const [dragOver, setDragOver] = useState(false)
  const [consentWait, setConsentWait] = useState(false)
  const consented = useRef(false)
  const pendingMutations = useRef(0)
  const fileInput = useRef<HTMLInputElement>(null)
  const uploadSeq = useRef(0)
  const uploadQueue = useRef<Promise<void>>(Promise.resolve())

  const g = effective.guardrails
  const reasonRequired = g.require_reason
  const ctx: FmContext = useMemo(() => ({ fmSession, reason: reasonSet ? reason : '' }), [fmSession, reason, reasonSet])
  const canWrite = fileOpDenied(effective, 'write') === null
  const canDelete = fileOpDenied(effective, 'delete') === null
  const ready = availability.available && (!reasonRequired || reasonSet)

  const list = useQuery({
    queryKey: [...remoteKeys.files(deviceId, path), fmSession],
    queryFn: () => withReauth(() => remoteApi.listFiles(deviceId, path, ctx)),
    enabled: ready,
    retry: false,
    staleTime: 15_000,
  })

  // Abort running uploads when the tab unmounts.
  const uploadsRef = useRef(uploads)
  uploadsRef.current = uploads
  useEffect(() => () => uploadsRef.current.forEach((u) => u.status === 'uploading' && u.handle?.abort()), [])

  const refresh = () => void qc.invalidateQueries({ queryKey: ['device', deviceId, 'files'] })
  const go = (p: string) => {
    setPath(p)
    setSelected(null)
    setEditing(false)
    setPathError(null)
  }

  /** Mutations: show the consent wait (first non-read op of this fm_session) while pending. */
  async function mutating<T>(fn: () => Promise<T>): Promise<T> {
    pendingMutations.current += 1
    const t = g.require_consent && !consented.current ? setTimeout(() => setConsentWait(true), 400) : null
    try {
      const r = await withReauth(fn)
      consented.current = true
      return r
    } finally {
      if (t) clearTimeout(t)
      pendingMutations.current -= 1
      if (pendingMutations.current === 0) setConsentWait(false)
    }
  }

  const del = useMutation({
    mutationFn: (e: FileEntry) => mutating(() => remoteApi.remove(deviceId, e.path, e.kind === 'dir' && !e.reparse, ctx)),
    onMutate: (e) => setBusy((b) => ({ ...b, [e.path]: 'Deleting…' })),
    onSuccess: (r, e) => {
      setNotice({ kind: 'ok', text: `Deleted ${e.name}${r.removed > 1 ? ` (${r.removed} items removed)` : ''}.` })
      refresh()
    },
    onError: (err, e) => setNotice({ kind: 'error', text: `Couldn’t delete ${e.name}: ${remoteErrorText(err)}` }),
    onSettled: (_r, _e, e) => setBusy(({ [e.path]: _, ...rest }) => rest),
  })

  const download = async (e: FileEntry) => {
    setBusy((b) => ({ ...b, [e.path]: 'Preparing download…' }))
    try {
      await withReauth(() => downloadFile(deviceId, e.path, ctx))
      setNotice({ kind: 'ok', text: `Downloading ${e.name} (${formatBytes(e.size)}). Your browser shows the progress.` })
    } catch (err) {
      setNotice({ kind: 'error', text: `Couldn’t download ${e.name}: ${remoteErrorText(err)}` })
    } finally {
      setBusy(({ [e.path]: _, ...rest }) => rest)
    }
  }

  const startUploads = (files: File[]) => {
    if (!path || !canWrite) return
    const items: UploadItem[] = []
    for (const f of files) {
      const id = ++uploadSeq.current
      const nameErr = validateName(f.name)
      const target = joinPath(path, f.name)
      const v = validateRemotePath(target)
      const existing = (list.data?.entries ?? []).find((x) => x.name.toLowerCase() === f.name.toLowerCase())
      const overwriteErr = existing
        ? existing.kind !== 'file'
          ? 'A folder with this name already exists here.'
          : !canDelete
            ? 'A file with this name already exists. Replacing files counts as deleting and this device’s profile does not allow delete. Rename your file or upload to another folder.'
            : null
        : null
      const err = nameErr ?? (v.ok ? null : v.error) ?? overwriteErr
      items.push({ id, name: f.name, target: v.ok ? v.path : target, loaded: 0, total: f.size, status: err ? 'failed' : 'queued', error: err ?? undefined, replaces: !!existing && !err })
      if (!err) {
        // One upload at a time keeps the agent's transfer queue short.
        uploadQueue.current = uploadQueue.current.then(() => runUpload(id, f, v.ok ? v.path : target))
      }
    }
    setUploads((u) => [...items, ...u])
  }
  const patchUpload = (id: number, p: Partial<UploadItem>) => setUploads((us) => us.map((u) => (u.id === id ? { ...u, ...p } : u)))
  const runUpload = async (id: number, f: File, target: string) => {
    if (uploadsRef.current.find((u) => u.id === id)?.status === 'failed') return
    try {
      const r = await mutating(() => {
        const h = uploadFile(deviceId, target, f, ctx, (loaded, total) => patchUpload(id, { loaded, total }))
        patchUpload(id, { status: 'uploading', handle: h, loaded: 0 })
        return h.promise
      })
      patchUpload(id, { status: 'done', loaded: r.size, total: r.size, sha256: r.sha256, handle: undefined })
      refresh()
    } catch (err) {
      patchUpload(id, { status: 'failed', error: remoteErrorText(err), handle: undefined })
    }
  }

  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    if (!path || !canWrite) return
    const files: File[] = []
    const items = e.dataTransfer.items
    let skipped = 0
    for (let i = 0; i < items.length; i++) {
      const it = items[i]
      const entry = it.webkitGetAsEntry?.()
      if (entry?.isDirectory) {
        skipped++
        continue
      }
      const f = it.getAsFile()
      if (f) files.push(f)
    }
    if (skipped) setNotice({ kind: 'error', text: `${skipped} folder${skipped > 1 ? 's were' : ' was'} skipped. Upload files one folder at a time (create the folder first).` })
    startUploads(files)
  }

  const submitPath = () => {
    const raw = pathInput.trim().replace(/^"(.*)"$/, '$1')
    if (!raw) return go('')
    const v = validateRemotePath(raw)
    if (!v.ok) return setPathError(`That path isn’t valid: ${v.error}.`)
    go(v.path)
  }

  const entries = useMemo(() => sortEntries(list.data?.entries ?? [], sort.key, sort.desc), [list.data, sort])
  const open = (e: FileEntry) => {
    if (e.kind === 'dir' || e.kind === 'drive') go(e.path)
  }
  const segments = pathSegments(path)
  const parent = path ? (parentOf(path) ?? '') : null
  const folders = entries.filter((e) => e.kind === 'dir' || e.kind === 'drive').length

  if (!availability.available) return <RemoteUnavailable feature="files" availability={availability} policyId={policyId} />

  if (reasonRequired && !reasonSet) {
    return (
      <form
        className="max-w-xl space-y-3 rounded-lg border border-border bg-surface p-4"
        onSubmit={(e) => {
          e.preventDefault()
          if (reason.trim()) setReasonSet(true)
        }}
      >
        <p className="text-sm font-medium">Why are you opening {hostname}’s files?</p>
        <p className="text-sm text-fg-muted">This device’s remote-access profile requires a reason. It is recorded with every file operation in the audit log{g.require_consent ? ' and shown to the employee when you change something' : ''}.</p>
        <Field label="Reason" htmlFor="fm-reason">
          <Input id="fm-reason" autoFocus value={reason} maxLength={200} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Collecting the crash log for ticket IT-4821" />
        </Field>
        <Button type="submit" variant="primary" disabled={!reason.trim()}>
          Open file manager
        </Button>
      </form>
    )
  }

  const sortHeader = (key: SortKey, label: string, className?: string) => (
    <th className={cn('px-3 py-2 text-left font-medium', className)} aria-sort={sort.key === key ? (sort.desc ? 'descending' : 'ascending') : 'none'}>
      <button type="button" className="inline-flex items-center gap-1 hover:text-fg" onClick={() => setSort((s) => ({ key, desc: s.key === key ? !s.desc : false }))}>
        {label}
        {sort.key === key ? sort.desc ? <ArrowDown className="size-3" aria-hidden /> : <ArrowUp className="size-3" aria-hidden /> : null}
      </button>
    </th>
  )

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-border bg-surface">
        {/* Toolbar */}
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2" role="toolbar" aria-label="File manager">
          <Tooltip content={parent == null ? 'Already at the drive list' : 'Up one level'}>
            <span>
              <Button size="icon-sm" variant="ghost" aria-label="Up one level" disabled={parent == null} onClick={() => parent != null && go(parent)}>
                <ArrowUp />
              </Button>
            </span>
          </Tooltip>
          <Tooltip content="Refresh">
            <Button size="icon-sm" variant="ghost" aria-label="Refresh" onClick={refresh} disabled={list.isFetching}>
              <RefreshCw className={cn(list.isFetching && 'animate-spin')} />
            </Button>
          </Tooltip>
          <div className="min-w-0 flex-1">
            {editing ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  submitPath()
                }}
              >
                <Label htmlFor="fm-path" className="sr-only">
                  Path
                </Label>
                <Input
                  id="fm-path"
                  autoFocus
                  value={pathInput}
                  onChange={(e) => {
                    setPathInput(e.target.value)
                    setPathError(null)
                  }}
                  onKeyDown={(e) => e.key === 'Escape' && (setEditing(false), setPathError(null))}
                  onBlur={() => !pathError && setEditing(false)}
                  aria-invalid={!!pathError}
                  aria-describedby={pathError ? 'fm-path-err' : undefined}
                  placeholder="C:\Users\… (empty = drive list)"
                  className="font-mono text-[13px]"
                />
              </form>
            ) : (
              <nav aria-label="Current folder" className="flex h-8 min-w-0 items-center rounded-md border border-border-strong bg-surface px-1">
                <ol className="flex min-w-0 flex-1 items-center overflow-x-auto text-[13px]">
                  <li>
                    <button type="button" onClick={() => go('')} className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 hover:bg-surface-2" aria-current={path === '' ? 'page' : undefined}>
                      <Monitor className="size-3.5 text-fg-subtle" aria-hidden /> {hostname}
                    </button>
                  </li>
                  {segments.map((s, i) => (
                    <li key={s.path} className="flex items-center">
                      <ChevronRight className="size-3.5 shrink-0 text-fg-subtle" aria-hidden />
                      <button type="button" onClick={() => go(s.path)} className="whitespace-nowrap rounded px-1.5 py-0.5 font-mono hover:bg-surface-2" aria-current={i === segments.length - 1 ? 'page' : undefined}>
                        {s.label}
                      </button>
                    </li>
                  ))}
                </ol>
                <Tooltip content="Type a path">
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    aria-label="Edit path"
                    onClick={() => {
                      setPathInput(path)
                      setEditing(true)
                    }}
                  >
                    <Pencil />
                  </Button>
                </Tooltip>
              </nav>
            )}
          </div>
          {canWrite ? (
            <>
              <Button size="sm" onClick={() => fileInput.current?.click()} disabled={!path}>
                <Upload /> Upload
              </Button>
              <input
                ref={fileInput}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => {
                  startUploads([...(e.target.files ?? [])])
                  e.target.value = ''
                }}
              />
              <Button size="sm" onClick={() => setDialog({ kind: 'mkdir' })} disabled={!path}>
                <FolderPlus /> New folder
              </Button>
            </>
          ) : null}
        </div>
        {pathError ? (
          <p id="fm-path-err" role="alert" className="border-b border-border bg-danger-soft px-3 py-1.5 text-xs">
            {pathError}
          </p>
        ) : null}
        <PermissionLine effective={effective} reason={ctx.reason} />
        {consentWait ? (
          <p role="status" className="flex items-center gap-2 border-b border-border bg-accent-soft px-3 py-2 text-sm">
            <Hourglass className="size-4 shrink-0 text-accent-text" aria-hidden /> Waiting for the employee to allow access… (up to {consentTimeout(g)} s). They see an Allow / Deny prompt with your name{ctx.reason ? ' and reason' : ''}.
          </p>
        ) : null}
        {notice ? (
          <div role={notice.kind === 'error' ? 'alert' : 'status'} className={cn('flex items-start gap-2 border-b border-border px-3 py-2 text-sm', notice.kind === 'error' ? 'bg-danger-soft' : 'bg-ok-soft')}>
            {notice.kind === 'error' ? <AlertCircle className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden /> : <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />}
            <span className="min-w-0 flex-1">
              {notice.text}
              {notice.kind === 'error' && notice.text.includes(MFA_NOT_ENABLED_TEXT) ? <MfaSetupLink className="ml-1.5" /> : null}
            </span>
            <Button size="icon-sm" variant="ghost" aria-label="Dismiss" onClick={() => setNotice(null)}>
              <X />
            </Button>
          </div>
        ) : null}
        {uploads.length ? <UploadList uploads={uploads} onClear={() => setUploads((u) => u.filter((x) => x.status === 'uploading' || x.status === 'queued'))} /> : null}

        {/* Listing + drop zone */}
        <div
          className="relative"
          onDragOver={(e) => {
            if (!path || !canWrite || !e.dataTransfer.types.includes('Files')) return
            e.preventDefault()
            setDragOver(true)
          }}
          onDragLeave={(e) => {
            if (e.currentTarget.contains(e.relatedTarget as Node | null)) return
            setDragOver(false)
          }}
          onDrop={onDrop}
        >
          {dragOver ? (
            <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center border-2 border-dashed border-accent bg-accent-soft/80 text-sm font-medium">
              Drop to upload to <span className="ml-1 font-mono">{path}</span>
            </div>
          ) : null}
          {list.error ? (
            <div role="alert" className="flex flex-col items-center gap-2 px-6 py-10 text-center">
              <AlertCircle className="size-6 text-danger" aria-hidden />
              <p className="text-sm font-medium">Couldn’t open {path || 'the drive list'}</p>
              <p className="max-w-md text-sm text-fg-muted">{remoteErrorText(list.error)}</p>
              {mfaNotEnabled(list.error) ? <MfaSetupLink className="text-sm" /> : null}
              <div className="mt-1 flex gap-2">
                <Button size="sm" onClick={() => list.refetch()}>
                  <RefreshCw /> Try again
                </Button>
                {parent != null ? (
                  <Button size="sm" variant="ghost" onClick={() => go(parent)}>
                    <ArrowUp /> Go up
                  </Button>
                ) : null}
              </div>
            </div>
          ) : list.isPending ? (
            <div className="flex items-center justify-center gap-2 px-6 py-12 text-sm text-fg-muted" aria-busy="true">
              <Loader2 className="size-4 animate-spin" aria-hidden /> Asking the device for {path || 'its drives'}…
            </div>
          ) : (
            <div className="max-h-[560px] overflow-auto">
              <table className="w-full text-sm" aria-label={`Contents of ${path || 'the drive list'}`}>
                <thead className="sticky top-0 z-[1] bg-surface text-xs text-fg-subtle">
                  <tr className="border-b border-border">
                    {sortHeader('name', 'Name')}
                    <th className="px-3 py-2 text-left font-medium">Type</th>
                    {sortHeader('size', path ? 'Size' : 'Space', 'text-right [&>button]:ml-auto')}
                    {sortHeader('modified', 'Modified')}
                    <th className="px-3 py-2">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {entries.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-3 py-10 text-center text-sm text-fg-muted">
                        This folder is empty.{canWrite && path ? ' Drop files here or use Upload.' : ''}
                      </td>
                    </tr>
                  ) : (
                    entries.map((e) => (
                      <Row
                        key={e.path}
                        e={e}
                        selected={selected === e.path}
                        busy={busy[e.path]}
                        blocked={!!blockedPrefix(g, e.path)}
                        canDelete={canDelete && e.kind !== 'drive'}
                        onSelect={() => setSelected(e.path)}
                        onOpen={() => open(e)}
                        onDownload={() => void download(e)}
                        onRename={() => setDialog({ kind: 'rename', entry: e })}
                        onDelete={() => del.mutate(e)}
                      />
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <p className="flex flex-wrap gap-x-3 border-t border-border px-3 py-1.5 text-xs text-fg-subtle">
          <span>
            {folders} {path ? 'folders' : 'drives'}
            {path ? `, ${entries.length - folders} files` : ''}
          </span>
          {list.data?.truncated ? <span className="text-warn">Showing the first 10,000 entries only.</span> : null}
          <span className="ml-auto">Every operation runs as SYSTEM on the device and is recorded in the audit log.</span>
        </p>
      </div>
      {dialog ? (
        <NameDialog
          title={dialog.kind === 'mkdir' ? 'New folder' : `Rename ${dialog.entry.name}`}
          initial={dialog.kind === 'mkdir' ? '' : dialog.entry.name}
          folder={dialog.kind === 'mkdir' ? path : (parentOf(dialog.entry.path) ?? path)}
          action={dialog.kind === 'mkdir' ? 'Create' : 'Rename'}
          waiting={consentWait ? `Waiting for the employee to allow access… (up to ${consentTimeout(g)} s)` : null}
          onClose={() => setDialog(null)}
          onSubmit={async (target) => {
            if (dialog.kind === 'mkdir') {
              await mutating(() => remoteApi.mkdir(deviceId, target, ctx))
              setNotice({ kind: 'ok', text: `Created ${fileNameOf(target)}.` })
            } else {
              await mutating(() => remoteApi.rename(deviceId, dialog.entry.path, target, ctx))
              setNotice({ kind: 'ok', text: `Renamed ${dialog.entry.name} to ${fileNameOf(target)}.` })
            }
            refresh()
            setDialog(null)
          }}
        />
      ) : null}
    </div>
  )
}

function PermissionLine({ effective, reason }: { effective: RemoteAccessProfile; reason: string }) {
  const g = effective.guardrails
  const parts: string[] = []
  if (effective.files === 'read_only') parts.push('Read only: browse and download')
  else {
    if (!g.allow_upload) parts.push('Uploads and new folders are not allowed')
    if (!g.allow_delete) parts.push('Delete and rename are not allowed')
  }
  if (g.require_consent && effective.files === 'full') parts.push('changes need the employee’s consent')
  if (g.blocked_paths.length) parts.push(`${g.blocked_paths.length} blocked folder${g.blocked_paths.length > 1 ? 's' : ''}`)
  if (!parts.length && !reason) return null
  return (
    <p className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border px-3 py-1.5 text-xs text-fg-muted">
      <Lock className="size-3.5 text-fg-subtle" aria-hidden />
      {parts.length ? <span>{parts.join(' · ')}</span> : null}
      {reason ? <span className="truncate">Reason: “{reason}”</span> : null}
    </p>
  )
}

function Row({
  e,
  selected,
  busy,
  blocked,
  canDelete,
  onSelect,
  onOpen,
  onDownload,
  onRename,
  onDelete,
}: {
  e: FileEntry
  selected: boolean
  busy?: string
  blocked: boolean
  canDelete: boolean
  onSelect: () => void
  onOpen: () => void
  onDownload: () => void
  onRename: () => void
  onDelete: () => void
}) {
  const navigable = e.kind === 'dir' || e.kind === 'drive'
  const Icon = e.kind === 'drive' ? HardDrive : e.kind === 'link' ? Link2 : e.kind === 'dir' ? Folder : FileIcon
  const onKey = (k: KeyboardEvent) => {
    if (k.key === 'Enter' && navigable) {
      k.preventDefault()
      onOpen()
    }
  }
  return (
    <tr
      tabIndex={0}
      aria-selected={selected}
      onClick={onSelect}
      onDoubleClick={onOpen}
      onKeyDown={onKey}
      className={cn('group border-b border-border last:border-0 outline-none focus-visible:bg-accent-soft', selected ? 'bg-accent-soft' : 'hover:bg-surface-2/60', e.hidden && 'text-fg-muted')}
    >
      <td className="max-w-0 px-3 py-1.5">
        <div className="flex min-w-0 items-center gap-2">
          <Icon className={cn('size-4 shrink-0', navigable ? 'text-accent-text' : 'text-fg-subtle')} aria-hidden />
          {navigable ? (
            <button type="button" tabIndex={-1} onClick={onOpen} className="truncate text-left hover:underline">
              {e.kind === 'drive' ? <span className="font-mono">{e.name}</span> : e.name}
              {e.kind === 'drive' && e.label ? <span className="ml-1.5 text-fg-muted">{e.label}</span> : null}
            </button>
          ) : (
            <span className="truncate">{e.name}</span>
          )}
          {e.reparse ? <Chip>link</Chip> : null}
          {e.hidden ? <Chip>hidden</Chip> : null}
          {e.readonly && e.kind === 'file' ? <Chip>read-only</Chip> : null}
          {blocked ? <Chip tone="warn">blocked</Chip> : null}
          {busy ? (
            <span className="inline-flex items-center gap-1 text-xs text-fg-muted">
              <Loader2 className="size-3 animate-spin" aria-hidden /> {busy}
            </span>
          ) : null}
        </div>
      </td>
      <td className="whitespace-nowrap px-3 py-1.5 text-xs text-fg-muted">{e.reparse && e.kind !== 'link' ? `${KIND_LABEL[e.kind]} (link)` : KIND_LABEL[e.kind]}</td>
      <td className="whitespace-nowrap px-3 py-1.5 text-right text-xs tabular text-fg-muted">
        {e.kind === 'drive' ? (e.total_bytes ? `${formatBytes(e.free_bytes)} free of ${formatBytes(e.total_bytes)}` : '—') : e.kind === 'file' ? formatBytes(e.size) : ''}
      </td>
      <td className="whitespace-nowrap px-3 py-1.5 text-xs tabular text-fg-muted">{e.modified ? formatDateTime(e.modified) : ''}</td>
      <td className="w-px whitespace-nowrap px-2 py-1 text-right">
        <div className="flex items-center justify-end gap-1">
          {e.kind === 'file' ? (
            <Tooltip content={`Download ${e.name}`}>
              <Button size="icon-sm" variant="ghost" aria-label={`Download ${e.name}`} onClick={(ev) => (ev.stopPropagation(), onDownload())} disabled={!!busy}>
                <Download />
              </Button>
            </Tooltip>
          ) : null}
          {canDelete ? (
            <Dropdown>
              <DropdownTrigger asChild>
                <Button size="icon-sm" variant="ghost" aria-label={`More actions for ${e.name}`} disabled={!!busy} onClick={(ev) => ev.stopPropagation()}>
                  <MoreHorizontal />
                </Button>
              </DropdownTrigger>
              <DropdownContent>
                {navigable ? <DropdownItem onSelect={onOpen}>Open</DropdownItem> : null}
                {e.kind === 'file' ? (
                  <DropdownItem onSelect={onDownload}>
                    <Download /> Download
                  </DropdownItem>
                ) : null}
                <DropdownItem onSelect={onRename}>
                  <Pencil /> Rename
                </DropdownItem>
                <DropdownSeparator />
                <DropdownItem danger onSelect={onDelete}>
                  <Trash2 /> Delete{e.kind === 'dir' && !e.reparse ? ' folder and contents' : e.reparse ? ' link' : ''}
                </DropdownItem>
              </DropdownContent>
            </Dropdown>
          ) : null}
        </div>
      </td>
    </tr>
  )
}

function Chip({ children, tone }: { children: string; tone?: 'warn' }) {
  return <span className={cn('shrink-0 rounded border px-1 text-[10.5px] leading-4', tone === 'warn' ? 'border-warn/40 bg-warn-soft text-warn' : 'border-border bg-surface-2 text-fg-muted')}>{children}</span>
}

function UploadList({ uploads, onClear }: { uploads: UploadItem[]; onClear: () => void }) {
  const finished = uploads.some((u) => u.status === 'done' || u.status === 'failed')
  return (
    <div className="border-b border-border px-3 py-2">
      <div className="mb-1 flex items-center justify-between">
        <p className="text-xs font-medium text-fg-subtle">Uploads</p>
        {finished ? (
          <Button size="sm" variant="ghost" onClick={onClear}>
            Clear finished
          </Button>
        ) : null}
      </div>
      <ul className="space-y-1.5">
        {uploads.map((u) => {
          const pct = u.total ? Math.round((u.loaded / u.total) * 100) : u.status === 'done' ? 100 : 0
          return (
            <li key={u.id} className="text-xs">
              <div className="flex flex-wrap items-center gap-2">
                {u.status === 'done' ? (
                  <CheckCircle2 className="size-3.5 text-ok" aria-hidden />
                ) : u.status === 'failed' ? (
                  <AlertCircle className="size-3.5 text-danger" aria-hidden />
                ) : (
                  <Loader2 className="size-3.5 animate-spin text-fg-subtle" aria-hidden />
                )}
                <span className="font-medium">{u.name}</span>
                <span className="text-fg-subtle">→</span>
                <span className="min-w-0 truncate font-mono text-fg-muted" title={u.target}>
                  {u.target}
                </span>
                {u.replaces ? <span className="rounded border border-warn/40 bg-warn-soft px-1 text-[10.5px] text-warn">replaces existing file</span> : null}
                <span className="ml-auto tabular text-fg-muted">
                  {u.status === 'done' ? `Done · ${formatBytes(u.total)}` : u.status === 'failed' ? 'Failed' : u.status === 'queued' ? 'Waiting' : `${pct}% of ${formatBytes(u.total)}`}
                </span>
                {u.status === 'uploading' && u.handle ? (
                  <Button size="sm" variant="ghost" onClick={() => u.handle?.abort()}>
                    Cancel
                  </Button>
                ) : null}
              </div>
              {u.status === 'uploading' || u.status === 'queued' ? (
                <div className="mt-1 h-1.5 overflow-hidden rounded bg-surface-3" role="progressbar" aria-label={`Uploading ${u.name}`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
                  <div className="h-full bg-accent transition-[width]" style={{ width: `${pct}%` }} />
                </div>
              ) : null}
              {u.error ? <p className="mt-0.5 text-danger">{u.error}</p> : null}
              {u.sha256 ? <p className="mt-0.5 font-mono text-[10.5px] text-fg-subtle">SHA-256 {u.sha256.slice(0, 16)}… verified by the agent</p> : null}
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function NameDialog({ title, initial, folder, action, waiting, onClose, onSubmit }: { title: string; initial: string; folder: string; action: string; waiting: string | null; onClose: () => void; onSubmit: (target: string) => Promise<void> }) {
  const [name, setName] = useState(initial)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    const n = validateName(name)
    if (n) return setError(n)
    const v = validateRemotePath(joinPath(folder, name))
    if (!v.ok) return setError(`That name isn’t valid: ${v.error}.`)
    setBusy(true)
    setError(null)
    try {
      await onSubmit(v.path)
    } catch (e) {
      setError(remoteErrorText(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="sm"
        title={title}
        description={<span className="font-mono text-xs">{joinPath(folder, name || '…')}</span>}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={busy || !name.trim() || name === initial} onClick={() => void submit()}>
              {busy ? <Loader2 className="animate-spin" /> : null} {action}
            </Button>
          </>
        }
      >
        <form
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <Field label="Name" htmlFor="fm-name" error={error}>
            <Input id="fm-name" autoFocus value={name} onChange={(e) => (setName(e.target.value), setError(null))} />
          </Field>
          {waiting && busy ? (
            <p role="status" className="mt-3 flex items-center gap-2 text-sm text-fg-muted">
              <Hourglass className="size-4 shrink-0 text-accent-text" aria-hidden /> {waiting}
            </p>
          ) : null}
        </form>
      </DialogContent>
    </Dialog>
  )
}
