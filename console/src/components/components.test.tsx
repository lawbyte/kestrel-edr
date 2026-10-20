import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { TreeNode } from '@/api/types'
import { DeviceStatusBadge, ReleaseStateBadge, RingBadge, SeverityBadge } from './badges'
import { Markdown } from './markdown'
import { ProcessTree, buildForest } from './process-tree'
import { DataAtRiskPanel, priorityFactors } from './incident-parts'
import { TooltipProvider } from './ui/misc'

vi.mock('@/lib/auth', () => ({ useAuth: () => ({ me: { user: { id: 'u' }, privileges: ['*'] }, can: () => true }) }))

const node = (guid: string, parent: string | null, image: string, extra: Partial<TreeNode> = {}): TreeNode => ({
  guid,
  parent_guid: parent,
  pid: guid.length * 100,
  image,
  cmdline: image,
  user: null,
  start_ts: 1000 + guid.length,
  exit_ts: null,
  signer: null,
  signed: 'unsigned',
  sha256: null,
  path_class: 'temp',
  alert_rule_ids: [],
  is_root: parent == null,
  ...extra,
})

describe('SeverityBadge', () => {
  it('always renders a text label next to the icon', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })
  it('keeps the label for screen readers in compact mode', () => {
    render(<SeverityBadge severity="high" compact />)
    expect(screen.getByText('High')).toHaveClass('sr-only')
  })
})

describe('DeviceStatusBadge', () => {
  it('shows a text label, not only a coloured dot', () => {
    render(<DeviceStatusBadge status="isolated" />)
    expect(screen.getByText('Isolated')).toBeInTheDocument()
  })
})

describe('update badges', () => {
  it('label release state and ring in text, not only colour', () => {
    render(
      <>
        <ReleaseStateBadge state="halted" />
        <ReleaseStateBadge state="rolling" />
        <RingBadge ring="pinned" />
      </>,
    )
    expect(screen.getByText('Halted')).toBeInTheDocument()
    expect(screen.getByText('Rolling out')).toBeInTheDocument()
    expect(screen.getByText('Pinned')).toBeInTheDocument()
  })
})

describe('Markdown', () => {
  it('renders bold, code and lists without injecting HTML', () => {
    const { container } = render(<Markdown source={'**Hi** `x`\n\n- a\n- b\n\n<img src=x onerror=alert(1)>'} />)
    expect(container.querySelector('strong')?.textContent).toBe('Hi')
    expect(container.querySelector('code')?.textContent).toBe('x')
    expect(container.querySelectorAll('li')).toHaveLength(2)
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain('<img src=x onerror=alert(1)>')
  })
  it('only links http(s) and mailto URLs', () => {
    const { container } = render(<Markdown source={'[ok](https://a.b) [bad](javascript:alert(1))'} />)
    const links = container.querySelectorAll('a')
    expect(links).toHaveLength(1)
    expect(links[0].getAttribute('href')).toBe('https://a.b')
  })
})

describe('ProcessTree', () => {
  const nodes = [
    node('a', null, 'C:\\Windows\\explorer.exe', { path_class: 'windows', signed: 'valid', signer: 'Microsoft Windows' }),
    node('bb', 'a', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', { path_class: 'system', signed: 'valid', signer: 'Microsoft Windows' }),
    node('ccc', 'bb', 'C:\\Users\\x\\AppData\\Local\\Temp\\Setup_x64.exe', { alert_rule_ids: ['ST-04'] }),
  ]
  it('builds a forest from parent links', () => {
    const f = buildForest(nodes)
    expect(f).toHaveLength(1)
    expect(f[0].children[0].children[0].node.guid).toBe('ccc')
  })
  it('renders nodes with alert markers and calls onSelect', () => {
    const onSelect = vi.fn()
    render(
      <TooltipProvider>
        <ProcessTree nodes={nodes} selected={null} onSelect={onSelect} />
      </TooltipProvider>,
    )
    expect(screen.getAllByRole('treeitem')).toHaveLength(3)
    expect(screen.getByText('ST-04')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Setup_x64.exe'))
    expect(onSelect).toHaveBeenCalledWith('ccc')
  })
  it('collapses children', () => {
    render(
      <TooltipProvider>
        <ProcessTree nodes={nodes} selected={null} onSelect={() => {}} />
      </TooltipProvider>,
    )
    fireEvent.click(screen.getAllByRole('button', { name: 'Collapse' })[0])
    expect(screen.getAllByRole('treeitem')).toHaveLength(1)
  })
})

describe('DataAtRiskPanel', () => {
  it('shows labels and remediation, merging cookies and master key', () => {
    render(<DataAtRiskPanel categories={['browser_cookies', 'browser_master_key', 'crypto_wallet']} user="HL\\a" />)
    expect(screen.getByText('Browser cookies / sessions')).toBeInTheDocument()
    expect(screen.queryByText('Browser encryption key')).toBeNull()
    expect(screen.getByText(/fresh seed/)).toBeInTheDocument()
  })
  it('says so when nothing was touched', () => {
    render(<DataAtRiskPanel categories={[]} />)
    expect(screen.getByText(/No credential stores/)).toBeInTheDocument()
  })
})

describe('priorityFactors', () => {
  it('matches the contract formula', () => {
    const f = priorityFactors({ severity: 'critical', data_at_risk: ['browser_passwords'], rule_ids: ['ST-04'], contained: false } as never)
    expect(f.reduce((s, x) => s + x.points, 0)).toBe(115)
  })
})
