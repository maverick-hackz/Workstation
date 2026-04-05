# PNG / Image Analysis

> Quick look-up for steganography & metadata checks on images encountered in CTF and forensic triage. Authorized testing only.

## TL;DR
- `steghide info <file>` reports whether a JPEG/BMP/WAV/AU carrier looks tampered (note: steghide does not support PNG).
- For PNG/GIF stego use `zsteg`, `stegsolve`, `pngcheck`, or `exiftool`.
- Always start with `exiftool` and `strings` — most CTF "stego" is just hidden metadata or appended bytes.

## Detection / Discovery
| Command | Description |
| --- | --- |
| `steghide info <FILE_NAME>` | Inspect a JPEG/BMP/WAV/AU carrier; prompts for the passphrase to confirm embedded data |
| `exiftool <FILE_NAME>` | Dump metadata (EXIF/IPTC/XMP) |
| `pngcheck -v <FILE_NAME>` | Validate PNG chunks and decode warnings |
| `zsteg <FILE_NAME>` | LSB / common-channel decoder for PNG/BMP |
| `strings -n 8 <FILE_NAME>` | Cheap "appended data" check |

## Defence / Remediation
- Strip metadata server-side (`exiftool -all=`) before serving user-uploaded images on production.
- Re-encode rather than re-host raw uploads (Pillow/ImageMagick decode → encode) — CWE-117 Improper Output Neutralization.
- Enforce strict content-type detection (magic bytes) instead of trusting client-supplied MIME.

## Sources
- steghide manual: https://steghide.sourceforge.net/
- pngcheck: http://www.libpng.org/pub/png/apps/pngcheck.html
- zsteg: https://github.com/zed-0xff/zsteg
- exiftool: https://exiftool.org/
