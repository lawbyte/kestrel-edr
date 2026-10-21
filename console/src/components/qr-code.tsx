import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { cn } from '@/lib/utils'

/**
 * A QR code rendered locally as SVG (nothing leaves the browser). Always dark
 * modules on white with a quiet zone, in both themes, so phone cameras read it.
 */
export function QrCode({ value, label, size = 176, className }: { value: string; label: string; size?: number; className?: string }) {
  const [svg, setSvg] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let live = true
    setSvg(null)
    setFailed(false)
    QRCode.toString(value, { type: 'svg', errorCorrectionLevel: 'M', margin: 2, color: { dark: '#000000', light: '#ffffff' } })
      .then((s) => live && setSvg(s))
      .catch(() => live && setFailed(true))
    return () => {
      live = false
    }
  }, [value])
  return (
    <div className={cn('shrink-0 overflow-hidden rounded-lg border border-border bg-white p-1', className)} style={{ width: size + 10, height: size + 10 }}>
      {svg ? (
        <img src={`data:image/svg+xml;utf8,${encodeURIComponent(svg)}`} alt={label} width={size} height={size} className="block" data-testid="qr-code" />
      ) : (
        <div role={failed ? 'alert' : 'status'} className="flex size-full items-center justify-center p-3 text-center text-xs text-neutral-600">
          {failed ? 'The QR code could not be drawn. Enter the key by hand.' : 'Drawing QR code…'}
        </div>
      )}
    </div>
  )
}
