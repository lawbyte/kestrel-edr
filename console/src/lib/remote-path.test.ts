import { describe, expect, it } from 'vitest'
import { PATH_MAX_CHARS, fileNameOf, joinPath, parentOf, pathIsWithin, pathSegments, sortEntries, validateName, validateRemotePath } from './remote-path'

/** Same cases as `kestrel_common::remote::tests::paths_are_validated_and_normalised`. */
describe('validateRemotePath (mirror of validate_remote_path)', () => {
  const ok = (p: string) => {
    const r = validateRemotePath(p)
    if (!r.ok) throw new Error(`${p}: ${r.error}`)
    return r.path
  }
  it('normalises good paths', () => {
    expect(ok('c:')).toBe('C:\\')
    expect(ok('c:\\')).toBe('C:\\')
    expect(ok('c:/Users//bob/')).toBe('C:\\Users\\bob')
    expect(ok('D:\\a b\\c.txt')).toBe('D:\\a b\\c.txt')
    expect(ok('z:/')).toBe('Z:\\')
  })
  it('refuses everything the Rust side refuses', () => {
    for (const bad of [
      '',
      'Users\\bob',
      '\\\\server\\share\\x',
      '\\\\?\\C:\\x',
      '\\\\.\\PhysicalDrive0',
      'C:x',
      'C:\\a\\..\\Windows',
      'C:\\a\\.\\b',
      'C:\\a\\file.txt:stream',
      'C:\\a\\b.',
      'C:\\a\\b ',
      'C:\\a\\b*',
      'C:\\a\u0000b',
      'C:\\a\u0085b',
      '1:\\x',
      'C:\\a\\b?',
      'C:\\a\\<b>',
      'C:\\a|b',
      'C:\\"q"',
    ]) {
      expect(validateRemotePath(bad).ok, JSON.stringify(bad)).toBe(false)
    }
    expect(validateRemotePath(`C:\\${'a'.repeat(PATH_MAX_CHARS)}`).ok).toBe(false)
  })
  it('gives a plain reason', () => {
    const r = validateRemotePath('C:\\a\\..\\b')
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/'\.\.'/)
  })
})

describe('path helpers (mirror of parent_of / file_name_of / path_is_within)', () => {
  it('within', () => {
    expect(pathIsWithin('C:\\Program Files\\Kestrel', 'c:\\program files\\kestrel')).toBe(true)
    expect(pathIsWithin('C:\\Program Files\\Kestrel\\x.exe', 'C:\\Program Files\\Kestrel\\')).toBe(true)
    expect(pathIsWithin('C:\\Program Files\\Kestrel2', 'C:\\Program Files\\Kestrel')).toBe(false)
    expect(pathIsWithin('C:\\x', '')).toBe(false)
  })
  it('parents and names', () => {
    expect(parentOf('C:\\a\\b')).toBe('C:\\a')
    expect(parentOf('C:\\a')).toBe('C:\\')
    expect(parentOf('C:\\')).toBeNull()
    expect(fileNameOf('C:\\a\\b.txt')).toBe('b.txt')
    expect(joinPath('C:\\', 'x')).toBe('C:\\x')
    expect(joinPath('C:\\a', 'x')).toBe('C:\\a\\x')
  })
  it('breadcrumb segments', () => {
    expect(pathSegments('')).toEqual([])
    expect(pathSegments('C:\\')).toEqual([{ label: 'C:', path: 'C:\\' }])
    expect(pathSegments('C:\\Users\\bob')).toEqual([
      { label: 'C:', path: 'C:\\' },
      { label: 'Users', path: 'C:\\Users' },
      { label: 'bob', path: 'C:\\Users\\bob' },
    ])
  })
  it('validates single names', () => {
    expect(validateName('report.pdf')).toBeNull()
    expect(validateName('a/b')).toMatch(/\\/)
    expect(validateName('..')).toBeTruthy()
    expect(validateName('x:y')).toBeTruthy()
    expect(validateName('trailing.')).toBeTruthy()
    expect(validateName('  ')).toBeTruthy()
  })
})

describe('sortEntries', () => {
  const e = (name: string, kind: string, size = 0, modified: number | null = null) => ({ name, kind, size, modified })
  const list = [e('b.txt', 'file', 5, 3), e('Zeta', 'dir', 0, 1), e('a.txt', 'file', 50, 1), e('alpha', 'dir', 0, 9), e('file10', 'file', 1, 2), e('file2', 'file', 2, 2)]
  it('puts folders first and sorts names naturally', () => {
    expect(sortEntries(list, 'name').map((x) => x.name)).toEqual(['alpha', 'Zeta', 'a.txt', 'b.txt', 'file2', 'file10'])
  })
  it('sorts by size / modified within the groups, both directions', () => {
    expect(sortEntries(list, 'size').map((x) => x.name)).toEqual(['alpha', 'Zeta', 'file10', 'file2', 'b.txt', 'a.txt'])
    expect(sortEntries(list, 'size', true).map((x) => x.name)).toEqual(['Zeta', 'alpha', 'a.txt', 'b.txt', 'file2', 'file10'])
    expect(sortEntries(list, 'modified').map((x) => x.name)[0]).toBe('Zeta')
  })
})
