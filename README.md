
# FW Signature Diff GUI

A modern desktop GUI tool (Windows-first) to compare an **original** firmware binary against a **signed** firmware binary, identify changed regions/spans, and automatically **extract candidate signature blobs** (generic heuristics: RSA/ECDSA/Ed25519/Ed448 sizes, etc.).

It is especially useful when the signing process appends or replaces signature-like structures inside the image and you need to quickly isolate them as separate `.bin` chunks.

## Features

- Select **Original** and **Signed** binaries from a GUI.
- Fast diff by **block ranges** + precise **byte spans** inside each range.
- Generic “size-fit” heuristic: tries to represent the total changed bytes as a sum of known signature sizes (not RSA-only).
- Automatic extraction:
  - Export when a range matches a **Fit Target** (e.g. `384:2` meaning `384 bytes * 2`).
  - Export large contiguous spans above a configurable threshold.
- **Windows-safe filenames** (sanitizes invalid characters).
- Export output goes to a **timestamped folder** (prevents overwriting):
  - Example: `extracted_sigs\20260108_132015\...`
- Save a full analysis **JSON report**.
- Button to open the export folder in Windows Explorer.

## Requirements

- Windows 10/11 recommended.
- Python 3.11 x64 recommended (PySide6 availability depends on Python version).



## How to use

1. Click **Seleccionar original…** and choose your unsigned/original firmware file.
2. Click **Seleccionar firmado…** and choose your signed firmware file.
3. Adjust parameters if needed:
    - **Block size**: coarse diff granularity (default 1024).
    - **Contexto hex**: how many bytes to show around each span.
    - **Known sizes (CSV)**: list of signature sizes in bytes (example: `256,384,512,64,96,114,132`).
    - **Fit objetivo**: `SIZE:COUNT` (example `384:2`).
    - **Export dir (base)**: base folder; actual exports go into a timestamped subfolder.
    - **Min blob**: minimum contiguous span size to auto-export.
4. Click **Analizar**.
5. Review:
    - “Rangos distintos” table shows approximate changed ranges + fit info.
    - Selecting a range shows exact spans and hex previews.
6. Use **Abrir carpeta de exportación** to jump directly to extracted blobs.

## Output structure

Exports are saved under:

```
<export_dir_base>\<YYYYMMDD_HHMMSS>\
  fit_<...>.bin
  blob_<...>.bin
```

A JSON report can be saved via **Guardar JSON…**, containing:

- File sizes
- Settings used
- Changed ranges and spans
- Full list of exported files






## License

Choose one:

- MIT (simple, permissive)
- Apache-2.0 (explicit patent grant)


## Disclaimer

This tool performs **heuristic** blob detection and export. It does not cryptographically verify signatures; it helps you locate and extract candidate signature-like regions for further analysis.

