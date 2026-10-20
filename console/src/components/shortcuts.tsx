import { Dialog, DialogContent } from './ui/dialog'
import { Kbd } from './ui/misc'

const GROUPS: { title: string; items: [string[], string][] }[] = [
  {
    title: 'Anywhere',
    items: [
      [['⌘', 'K'], 'Command palette: jump to a page, device or incident'],
      [['/'], 'Search'],
      [['?'], 'Show this help'],
      [['G', 'O'], 'Go to Overview'],
      [['G', 'I'], 'Go to Incidents'],
      [['G', 'A'], 'Go to Alerts'],
      [['G', 'D'], 'Go to Devices'],
      [['G', 'H'], 'Go to Hunt'],
      [['G', 'P'], 'Go to Policies'],
    ],
  },
  {
    title: 'Queues (incidents, alerts, devices)',
    items: [
      [['J'], 'Next row'],
      [['K'], 'Previous row'],
      [['Enter'], 'Open the side drawer'],
      [['Shift', 'Enter'], 'Open the full page'],
      [['X'], 'Select row for bulk actions'],
      [['Esc'], 'Close the drawer'],
    ],
  },
  {
    title: 'Incident drawer',
    items: [
      [['↑'], 'Previous incident'],
      [['↓'], 'Next incident'],
      [['O'], 'Open the full incident page'],
    ],
  },
]

export function ShortcutsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Keyboard shortcuts" size="lg">
        <div className="grid gap-6 sm:grid-cols-2">
          {GROUPS.map((g) => (
            <div key={g.title} className={g.title === 'Anywhere' ? 'sm:row-span-2' : ''}>
              <h3 className="mb-2 text-xs font-medium text-fg-subtle">{g.title}</h3>
              <ul className="space-y-1.5">
                {g.items.map(([keys, label]) => (
                  <li key={label} className="flex items-center justify-between gap-3 text-sm">
                    <span className="text-fg-muted">{label}</span>
                    <span className="flex shrink-0 gap-1">
                      {keys.map((k) => (
                        <Kbd key={k}>{k}</Kbd>
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}
