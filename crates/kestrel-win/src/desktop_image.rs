//! Pure image helpers for remote desktop: downscaling (box filter),
//! change-detection hash, bounded JPEG encoding and frame pacing.
//! Platform independent and unit-tested everywhere.

use std::time::Duration;

/// A JPEG above this size is re-encoded at a lower quality so that one live
/// message (base64 + JSON) stays below `LIVE_MAX_MESSAGE` (1 MiB).
pub const JPEG_SOFT_MAX: usize = 700 * 1024;
/// JPEG dimensions are `u16`.
pub const MAX_DIM: u32 = 65_535;

/// Output size for `scale_pct` (clamped 25..=100) of `w` x `h`, at least 1 x 1
/// and at most [`MAX_DIM`] on each side.
pub fn scaled_dims(w: u32, h: u32, scale_pct: u8) -> (u32, u32) {
    let pct = scale_pct.clamp(25, 100) as u64;
    let f = |v: u32| (((v as u64 * pct) + 50) / 100).clamp(1, MAX_DIM as u64) as u32;
    (f(w.max(1)), f(h.max(1)))
}

/// Box-filter downscale of a 32-bit BGRA/BGRx image (`stride` bytes per
/// source row) to `dw` x `dh`. Each output pixel is the average of the
/// source pixels it covers (alpha forced to 255). Returns an empty vector if
/// the input is too short for the given geometry.
pub fn downscale_bgra(src: &[u8], stride: usize, w: u32, h: u32, dw: u32, dh: u32) -> Vec<u8> {
    let (w, h, dw, dh) = (
        w as usize,
        h as usize,
        dw.max(1) as usize,
        dh.max(1) as usize,
    );
    if w == 0 || h == 0 || stride < w * 4 || src.len() < stride * (h - 1) + w * 4 {
        return Vec::new();
    }
    let mut out = vec![0u8; dw * dh * 4];
    // Precompute horizontal spans.
    let xs: Vec<(usize, usize)> = (0..dw)
        .map(|x| {
            let a = x * w / dw;
            let b = ((x + 1) * w / dw).max(a + 1).min(w);
            (a, b)
        })
        .collect();
    let mut acc = vec![[0u32; 3]; dw];
    for y in 0..dh {
        let y0 = y * h / dh;
        let y1 = ((y + 1) * h / dh).max(y0 + 1).min(h);
        for a in acc.iter_mut() {
            *a = [0; 3];
        }
        for sy in y0..y1 {
            let row = &src[sy * stride..sy * stride + w * 4];
            for (x, &(a, b)) in xs.iter().enumerate() {
                let s = &mut acc[x];
                for px in row[a * 4..b * 4].as_chunks::<4>().0 {
                    s[0] += px[0] as u32;
                    s[1] += px[1] as u32;
                    s[2] += px[2] as u32;
                }
            }
        }
        let rows = (y1 - y0) as u32;
        for (x, &(a, b)) in xs.iter().enumerate() {
            let n = rows * (b - a) as u32;
            let o = (y * dw + x) * 4;
            for c in 0..3 {
                out[o + c] = ((acc[x][c] + n / 2) / n) as u8;
            }
            out[o + 3] = 255;
        }
    }
    out
}

/// Fast change-detection hash of an image buffer (CRC-32 of the pixels mixed
/// with the dimensions).
pub fn frame_hash(buf: &[u8], w: u32, h: u32) -> u64 {
    let crc = crc32fast::hash(buf) as u64;
    (crc << 32) ^ ((w as u64) << 16) ^ (h as u64) ^ ((buf.len() as u64) << 40)
}

/// Encode BGRA/BGRx pixels (`w * h * 4` bytes, no row padding) as a baseline
/// JPEG.
pub fn encode_jpeg(bgra: &[u8], w: u32, h: u32, quality: u8) -> Result<Vec<u8>, String> {
    if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM {
        return Err(format!("image size {w}x{h} out of range"));
    }
    let mut out = Vec::with_capacity((w as usize * h as usize) / 8);
    let enc = jpeg_encoder::Encoder::new(&mut out, quality.clamp(1, 100));
    enc.encode(bgra, w as u16, h as u16, jpeg_encoder::ColorType::Bgra)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Qualities to try, best first, for a requested quality.
pub fn quality_ladder(q: u8) -> Vec<u8> {
    let q = q.clamp(10, 100);
    let mut v = vec![q, (q as u16 * 2 / 3) as u8, 20, 10];
    v.retain(|&x| x <= q);
    v.dedup();
    v.sort_unstable_by(|a, b| b.cmp(a));
    v.dedup();
    v
}

/// Encode so the JPEG is at most `max` bytes: the quality ladder first, then
/// halving the size (box filter) at quality 20 up to three times. Returns
/// `(jpeg, width, height)`.
pub fn encode_bounded(
    bgra: &[u8],
    w: u32,
    h: u32,
    quality: u8,
    max: usize,
) -> Result<(Vec<u8>, u32, u32), String> {
    let mut last = None;
    for q in quality_ladder(quality) {
        let j = encode_jpeg(bgra, w, h, q)?;
        if j.len() <= max {
            return Ok((j, w, h));
        }
        last = Some(j);
    }
    let (mut buf, mut cw, mut ch) = (None::<Vec<u8>>, w, h);
    for _ in 0..3 {
        if cw < 2 || ch < 2 {
            break;
        }
        let (nw, nh) = (cw / 2, ch / 2);
        let src = buf.as_deref().unwrap_or(bgra);
        let next = downscale_bgra(src, cw as usize * 4, cw, ch, nw, nh);
        let j = encode_jpeg(&next, nw, nh, 20)?;
        if j.len() <= max {
            return Ok((j, nw, nh));
        }
        last = Some(j);
        buf = Some(next);
        cw = nw;
        ch = nh;
    }
    Err(format!(
        "frame does not fit in {max} bytes (last attempt {} bytes)",
        last.map(|j| j.len()).unwrap_or(0)
    ))
}

/// Target interval between captures for `max_fps` (clamped 1..=15).
pub fn frame_interval(max_fps: u8) -> Duration {
    Duration::from_millis(1000 / max_fps.clamp(1, 15) as u64)
}

/// Delay before the next capture after one took `work`: the remainder of the
/// interval, or — when capture + encoding is slower than the target — half
/// the work time again, so a slow machine is not pinned at 100 % of a core.
/// Never more than 2 s.
pub fn next_delay(interval: Duration, work: Duration) -> Duration {
    let d = if work < interval {
        interval - work
    } else {
        work / 2
    };
    d.min(Duration::from_secs(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dims() {
        assert_eq!(scaled_dims(1920, 1080, 100), (1920, 1080));
        assert_eq!(scaled_dims(1920, 1080, 50), (960, 540));
        assert_eq!(scaled_dims(1920, 1080, 10), (480, 270), "clamped to 25 %");
        assert_eq!(scaled_dims(1366, 768, 75), (1025, 576));
        assert_eq!(scaled_dims(1, 1, 25), (1, 1));
        assert_eq!(scaled_dims(0, 0, 100), (1, 1));
        assert_eq!(scaled_dims(200_000, 10, 100).0, MAX_DIM);
    }

    fn img(w: u32, h: u32, mut f: impl FnMut(u32, u32) -> [u8; 4]) -> Vec<u8> {
        let mut v = Vec::new();
        for y in 0..h {
            for x in 0..w {
                v.extend_from_slice(&f(x, y));
            }
        }
        v
    }

    #[test]
    fn downscale_averages() {
        // 2x2 → 1x1: average of the four pixels.
        let src = [10, 20, 30, 0, 30, 40, 50, 0, 50, 60, 70, 0, 70, 80, 90, 0];
        assert_eq!(downscale_bgra(&src, 8, 2, 2, 1, 1), vec![40, 50, 60, 255]);
        // 4x2 checkerboard of 0/200 → 2x1 of 100.
        let src = img(4, 2, |x, y| {
            let v = if (x + y) % 2 == 0 { 0 } else { 200 };
            [v, v, v, 0]
        });
        assert_eq!(
            downscale_bgra(&src, 16, 4, 2, 2, 1),
            vec![100, 100, 100, 255, 100, 100, 100, 255]
        );
        // Identity size copies (alpha forced).
        let src = img(3, 2, |x, y| [x as u8, y as u8, 7, 1]);
        let out = downscale_bgra(&src, 12, 3, 2, 3, 2);
        assert_eq!(out, img(3, 2, |x, y| [x as u8, y as u8, 7, 255]));
        // Row padding (stride > w*4) is skipped.
        let mut padded = vec![0u8; 2 * 12];
        padded[0..4].copy_from_slice(&[100, 100, 100, 0]);
        padded[12..16].copy_from_slice(&[200, 200, 200, 0]);
        padded[4..8].copy_from_slice(&[255, 255, 255, 255]); // padding byte area
        assert_eq!(
            downscale_bgra(&padded, 12, 1, 2, 1, 1),
            vec![150, 150, 150, 255]
        );
        // Non-integer ratio still covers every pixel and stays in bounds.
        let src = img(7, 5, |_, _| [9, 9, 9, 9]);
        let out = downscale_bgra(&src, 28, 7, 5, 3, 2);
        assert_eq!(out.len(), 3 * 2 * 4);
        assert!(out.chunks(4).all(|p| p == [9, 9, 9, 255]));
        // Short input is refused, not a panic.
        assert!(downscale_bgra(&[0; 10], 8, 2, 2, 1, 1).is_empty());
    }

    #[test]
    fn hash_detects_changes() {
        let a = img(16, 16, |x, y| [x as u8, y as u8, 0, 0]);
        let mut b = a.clone();
        assert_eq!(frame_hash(&a, 16, 16), frame_hash(&b, 16, 16));
        b[100] ^= 1;
        assert_ne!(frame_hash(&a, 16, 16), frame_hash(&b, 16, 16));
        assert_ne!(frame_hash(&a, 16, 16), frame_hash(&a, 32, 8));
    }

    #[test]
    fn jpeg_encoding() {
        let src = img(64, 48, |x, y| [(x * 4) as u8, (y * 5) as u8, 128, 0]);
        let j = encode_jpeg(&src, 64, 48, 60).unwrap();
        assert_eq!(&j[..2], &[0xFF, 0xD8]);
        assert_eq!(&j[j.len() - 2..], &[0xFF, 0xD9]);
        assert!(encode_jpeg(&src, 0, 48, 60).is_err());
        assert!(encode_jpeg(&src[..10], 64, 48, 60).is_err());
        let (j2, w, h) = encode_bounded(&src, 64, 48, 90, JPEG_SOFT_MAX).unwrap();
        assert_eq!((w, h), (64, 48));
        assert!(j2.len() <= JPEG_SOFT_MAX);
    }

    #[test]
    fn bounded_encoding_shrinks() {
        // Noise compresses badly: force the ladder and the downscale path.
        let mut seed = 0x1234_5678u32;
        let src = img(256, 256, |_, _| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let b = seed.to_le_bytes();
            [b[0], b[1], b[2], 0]
        });
        let full = encode_jpeg(&src, 256, 256, 90).unwrap().len();
        let cap = full / 6;
        let (j, w, h) = encode_bounded(&src, 256, 256, 90, cap).unwrap();
        assert!(j.len() <= cap);
        assert!(w <= 256 && h <= 256);
        assert!(encode_bounded(&src, 256, 256, 90, 10).is_err());
    }

    #[test]
    fn ladder() {
        assert_eq!(quality_ladder(60), vec![60, 40, 20, 10]);
        assert_eq!(quality_ladder(30), vec![30, 20, 10]);
        assert_eq!(quality_ladder(90), vec![90, 60, 20, 10]);
        assert_eq!(quality_ladder(15), vec![15, 10]);
    }

    #[test]
    fn pacing() {
        let i = frame_interval(8);
        assert_eq!(i, Duration::from_millis(125));
        assert_eq!(frame_interval(0), Duration::from_millis(1000));
        assert_eq!(frame_interval(100), Duration::from_millis(66));
        assert_eq!(
            next_delay(i, Duration::from_millis(25)),
            Duration::from_millis(100)
        );
        assert_eq!(
            next_delay(i, Duration::from_millis(300)),
            Duration::from_millis(150)
        );
        assert_eq!(
            next_delay(i, Duration::from_secs(10)),
            Duration::from_secs(2)
        );
    }
}
