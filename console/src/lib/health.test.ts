import { describe, expect, it } from 'vitest'
import { eventsLostDetail } from './health'
import { describeFileActivity } from './events'

describe('eventsLostDetail', () => {
  it('keeps the total for older agents', () => {
    expect(eventsLostDetail({ etw_events_lost: 12, etw_buffers_lost: 1 })).toBe('12 events, 1 buffer')
    expect(eventsLostDetail({})).toBe('0 events, 0 buffers')
    expect(eventsLostDetail({ etw_events_lost: 5, etw_kernel_events_lost: null, sensor_internal_dropped: null })).toBe('5 events, 0 buffers')
  })
  it('splits Windows and Kestrel losses when the agent reports them', () => {
    expect(eventsLostDetail({ etw_events_lost: 1200, etw_buffers_lost: 3, etw_kernel_events_lost: 1000, sensor_internal_dropped: 200 })).toBe(
      '1000 lost by Windows, 200 dropped by Kestrel; 3 buffers',
    )
    expect(eventsLostDetail({ etw_events_lost: 0, etw_kernel_events_lost: 0, sensor_internal_dropped: 0 })).toBe('0 lost by Windows, 0 dropped by Kestrel; 0 buffers')
    // One side missing: derived from the total.
    expect(eventsLostDetail({ etw_events_lost: 50, etw_kernel_events_lost: 30 })).toBe('30 lost by Windows, 20 dropped by Kestrel; 0 buffers')
  })
})

describe('describeFileActivity (1.1.6 self_created)', () => {
  const base = { window_ms: 8000, files_touched: 160, dirs: 8, renames: 160 }
  it('names the files the process created itself', () => {
    expect(describeFileActivity({ ...base, new_files: 20, self_created: 120 })).toBe(
      'Renamed 160 files in 8 folders within 8.0 s (120 created by the process itself, 40 existing files)',
    )
  })
  it('is unchanged for older agents', () => {
    expect(describeFileActivity(base)).toBe('Renamed 160 files in 8 folders within 8.0 s')
  })
})
