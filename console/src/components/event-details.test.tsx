import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { KEvent } from '@/api/types'
import { EventDetails } from './event-details'

const answers = Array.from({ length: 20 }, (_, i) => `10.0.0.${i}`)
const dns: KEvent = { ts: 1_700_000_000_000, pid: 7, guid: 'g', type: 'dns_query', qname: '<img src=x onerror=alert(1)>.example', answers }

describe('EventDetails', () => {
  it('renders plain text, hides raw JSON until asked and expands DNS answers', () => {
    const { container } = render(<EventDetails event={dns} />)
    expect(screen.getByText('What happened')).toBeInTheDocument()
    expect(screen.getByText('Key fields')).toBeInTheDocument()
    // Endpoint strings are text, never markup.
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('a')).toBeNull()
    expect(screen.queryByText(/"type": "dns_query"/)).toBeNull()
    expect(screen.queryByText('10.0.0.5')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '+17 more' }))
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Show raw event' }))
    expect(screen.getByText(/"type": "dns_query"/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy raw event' })).toBeInTheDocument()
  })
})
