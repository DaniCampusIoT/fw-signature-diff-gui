#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import traceback
from dataclasses import dataclass
from hashlib import blake2b
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from tqdm import tqdm

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QAction
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSpinBox, QPlainTextEdit, QTableWidget,
    QTableWidgetItem, QGroupBox, QFormLayout, QSplitter, QMessageBox, QCheckBox
)

# ------------------------
# Core analysis utilities
# ------------------------

def hash_chunk(data: bytes) -> str:
    return blake2b(data, digest_size=16).hexdigest()

def hexdump(data: bytes, start: int, length: int) -> str:
    chunk = data[start:start + length]
    return " ".join(f"{b:02x}" for b in chunk)

def merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not intervals:
        return []
    intervals = sorted(intervals)
    out = [[intervals[0][0], intervals[0][1]]]
    for s, e in intervals[1:]:
        if s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]

def find_changed_ranges_by_blocks(a: bytes, b: bytes, block_size: int, progress_cb=None) -> List[Tuple[int, int]]:
    max_len = max(len(a), len(b))
    nblocks = (max_len + block_size - 1) // block_size
    intervals = []

    for bi in range(nblocks):
        if progress_cb and (bi % 8 == 0 or bi == nblocks - 1):
            progress_cb(int(100 * bi / max(1, nblocks)))

        off = bi * block_size
        a_blk = a[off:off + block_size]
        b_blk = b[off:off + block_size]
        if a_blk == b_blk:
            continue
        intervals.append((off, min(off + block_size, max_len)))

    if progress_cb:
        progress_cb(100)

    return merge_intervals(intervals)

def exact_diff_spans(a: bytes, b: bytes, start: int, end: int) -> List[Tuple[int, int]]:
    spans = []
    in_run = False
    run_s = None
    for i in range(start, end):
        diff = a[i] != b[i]
        if diff and not in_run:
            in_run = True
            run_s = i
        elif not diff and in_run:
            spans.append((run_s, i))
            in_run = False
            run_s = None
    if in_run:
        spans.append((run_s, end))
    return spans

def fit_as_sum(total: int, allowed_sizes: List[int], max_count: int = 6) -> Optional[Dict[int, int]]:
    best = None
    sizes = sorted(set([s for s in allowed_sizes if s > 0]), reverse=True)

    def rec(i, remaining, counts):
        nonlocal best
        if remaining == 0:
            parts = sum(counts.values())
            if best is None or parts < sum(best.values()):
                best = dict(counts)
            return
        if i == len(sizes):
            return
        s = sizes[i]
        for c in range(0, max_count + 1):
            rem2 = remaining - c * s
            if rem2 < 0:
                continue
            counts[s] = c
            rec(i + 1, rem2, counts)
        counts.pop(s, None)

    rec(0, total, {})
    if best is None:
        return None
    return {k: v for k, v in best.items() if v}

def fit_to_str(fit: Optional[Dict[int, int]]) -> str:
    if not fit:
        return ""
    items = sorted(fit.items(), key=lambda kv: kv[0], reverse=True)
    return " + ".join([f"{k}*{v}" for k, v in items])

def sanitize_filename(name: str) -> str:
    bad = '<>:"/\\|?*'
    out = "".join(("_" if c in bad else c) for c in name)
    out = out.strip().rstrip(".").rstrip(" ")
    return out or "file"

def write_bin(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def timestamp_folder() -> str:
    # YYYYMMDD_HHMMSS (sin ':' para Windows)
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ------------------------
# Signature "profiles" (generic)
# ------------------------

@dataclass
class SigProfile:
    name: str
    sizes: List[int]  # bytes

DEFAULT_PROFILES = [
    SigProfile("RSA (common)", [256, 384, 512]),
    SigProfile("ECDSA raw (common)", [64, 96, 132]),
    SigProfile("Ed25519", [64]),
    SigProfile("Ed448", [114]),
    SigProfile("ASN.1/DER-ish (approx)", [70, 71, 72, 73, 104, 105, 106]),
]

def parse_sizes_csv(s: str) -> List[int]:
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return out

def parse_fit_target(s: str) -> Dict[int, int]:
    size_s, count_s = s.split(":")
    return {int(size_s): int(count_s)}

# ------------------------
# Analyzer (pair)
# ------------------------

def analyze_pair(
    orig_path: str,
    signed_path: str,
    block_size: int,
    context: int,
    known_sizes: List[int],
    fit_target: Dict[int, int],
    export_dir: str,
    export_on_fit: bool,
    export_big_contig: bool,
    big_blob_min: int,
    progress_cb=None,
    log_cb=None
) -> Dict:
    def log(msg: str):
        if log_cb:
            log_cb(msg)

    # Export dir con timestamp (subcarpeta)
    export_base = export_dir.strip() or "extracted_sigs"
    export_dir_actual = os.path.join(export_base, timestamp_folder())
    os.makedirs(export_dir_actual, exist_ok=True)

    log(f"Export dir (actual): {export_dir_actual}")
    log(f"Loading files...\n  orig:   {orig_path}\n  signed: {signed_path}")

    with open(orig_path, "rb") as f:
        orig = f.read()
    with open(signed_path, "rb") as f:
        signed = f.read()

    log(f"Sizes: {len(orig)} -> {len(signed)} (delta {len(signed)-len(orig)})")

    ranges = find_changed_ranges_by_blocks(orig, signed, block_size, progress_cb=progress_cb)
    log(f"Changed ranges (approx blocks): {len(ranges)}")

    ranges_detail = []
    exports = []

    for ri, (rs, re) in enumerate(ranges):
        spans = exact_diff_spans(orig, signed, rs, re)
        total = sum((e - s) for s, e in spans)
        fit = fit_as_sum(total, known_sizes)

        span_objs = []
        for (s, e) in spans:
            ln = e - s
            span_objs.append({
                "start": s,
                "end": e,
                "length": ln,
                "orig_preview_hex": hexdump(orig, s, min(32, ln)) if ln else "",
                "signed_preview_hex": hexdump(signed, s, min(32, ln)) if ln else "",
                "orig_context_hex": hexdump(orig, max(0, s - context),
                                            min(len(orig), e + context) - max(0, s - context)),
                "signed_context_hex": hexdump(signed, max(0, s - context),
                                              min(len(signed), e + context) - max(0, s - context)),
            })

        rd = {
            "range_start": rs,
            "range_end": re,
            "range_len": re - rs,
            "num_spans": len(spans),
            "total_changed_bytes_in_range": total,
            "size_fit": fit,
            "spans": span_objs,
            "exported_files": [],  # NUEVO: lista de exports asociados a este rango
        }
        ranges_detail.append(rd)

        # --- Export rules ---
        if export_on_fit and fit == fit_target:
            if len(spans) == 1 and (spans[0][1] - spans[0][0]) == total:
                s, e = spans[0]
                blob = signed[s:e]
                h = hash_chunk(blob)

                fit_tag = fit_to_str(fit).replace(" ", "")
                fit_tag = fit_tag.replace("*", "x").replace("+", "_")
                base = f"fit_{fit_tag}_0x{rs:08X}_0x{re:08X}_contig_0x{s:08X}_0x{e:08X}_{h}.bin"
                base = sanitize_filename(base)

                outp = os.path.join(export_dir_actual, base)
                write_bin(outp, blob)
                exports.append(outp)
                rd["exported_files"].append(outp)
                log(f"Exported (fit target, contig): {outp}")

                if len(fit_target) == 1:
                    k, v = list(fit_target.items())[0]
                    if v == 2 and total == 2 * k:
                        mid = s + k
                        b1 = signed[s:mid]
                        b2 = signed[mid:e]

                        base1 = sanitize_filename(f"fit_{k}x2_part1_0x{s:08X}_0x{mid:08X}_{hash_chunk(b1)}.bin")
                        base2 = sanitize_filename(f"fit_{k}x2_part2_0x{mid:08X}_0x{e:08X}_{hash_chunk(b2)}.bin")

                        out1 = os.path.join(export_dir_actual, base1)
                        out2 = os.path.join(export_dir_actual, base2)
                        write_bin(out1, b1)
                        write_bin(out2, b2)
                        exports.extend([out1, out2])
                        rd["exported_files"].extend([out1, out2])
                        log(f"Exported (split): {out1}")
                        log(f"Exported (split): {out2}")
            else:
                for idx, (s, e) in enumerate(spans):
                    blob = signed[s:e]
                    base = sanitize_filename(f"fit_target_span{idx}_0x{s:08X}_0x{e:08X}_{hash_chunk(blob)}.bin")
                    outp = os.path.join(export_dir_actual, base)
                    write_bin(outp, blob)
                    exports.append(outp)
                    rd["exported_files"].append(outp)
                log(f"Exported (fit target, fragmented): {len(spans)} spans")

        if export_big_contig:
            for (s, e) in spans:
                ln = e - s
                if ln < big_blob_min:
                    continue
                blob = signed[s:e]
                base = sanitize_filename(f"blob_{ln}B_0x{s:08X}_0x{e:08X}_{hash_chunk(blob)}.bin")
                outp = os.path.join(export_dir_actual, base)
                write_bin(outp, blob)
                exports.append(outp)
                rd["exported_files"].append(outp)
                log(f"Exported (big blob): {outp}")

    report = {
        "files": {
            "orig": {"name": orig_path, "size": len(orig)},
            "signed": {"name": signed_path, "size": len(signed)},
        },
        "settings": {
            "block_size": block_size,
            "context": context,
            "known_sizes": known_sizes,
            "fit_target": fit_target,
            "export_dir_base": export_base,
            "export_dir_actual": export_dir_actual,
            "export_on_fit": export_on_fit,
            "export_big_contig": export_big_contig,
            "big_blob_min": big_blob_min,
            "note": "size_fit is a generic heuristic: tries to express total_changed_bytes_in_range as sum of known chunk sizes.",
        },
        "diff": {
            "changed_ranges_approx": ranges,
            "ranges_detail": ranges_detail,
        },
        "exports": exports,
    }
    return report

# ------------------------
# Worker thread
# ------------------------

class AnalyzeWorker(QThread):
    progress = Signal(int)
    log = Signal(str)
    finished_ok = Signal(dict)
    finished_err = Signal(str)

    def __init__(self, params: dict):
        super().__init__()
        self.params = params

    def run(self):
        try:
            def progress_cb(p): self.progress.emit(int(p))
            def log_cb(m): self.log.emit(m)

            report = analyze_pair(
                progress_cb=progress_cb,
                log_cb=log_cb,
                **self.params
            )
            self.finished_ok.emit(report)
        except Exception:
            self.finished_err.emit(traceback.format_exc())

# ------------------------
# GUI
# ------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Diff & Signature Blob Extractor")
        self.resize(1200, 780)

        self.worker = None
        self.last_report = None
        self.last_export_dir = None

        self.orig_edit = QLineEdit()
        self.signed_edit = QLineEdit()

        btn_orig = QPushButton("Seleccionar original…")
        btn_signed = QPushButton("Seleccionar firmado…")
        btn_orig.clicked.connect(lambda: self.pick_file(self.orig_edit))
        btn_signed.clicked.connect(lambda: self.pick_file(self.signed_edit))

        self.block_size = QSpinBox()
        self.block_size.setRange(64, 1024 * 1024)
        self.block_size.setValue(1024)

        self.context = QSpinBox()
        self.context.setRange(0, 4096)
        self.context.setValue(32)

        self.profile_edit = QLineEdit()
        self.profile_edit.setText("256,384,512,64,96,114,132")

        self.fit_target = QLineEdit()
        self.fit_target.setText("384:2")

        self.export_dir = QLineEdit()
        self.export_dir.setText("extracted_sigs")

        self.chk_export_fit = QCheckBox("Exportar cuando encaje el fit objetivo")
        self.chk_export_fit.setChecked(True)

        self.chk_export_big = QCheckBox("Exportar blobs contiguos grandes")
        self.chk_export_big.setChecked(True)

        self.big_blob_min = QSpinBox()
        self.big_blob_min.setRange(1, 1024 * 1024)
        self.big_blob_min.setValue(256)

        self.btn_run = QPushButton("Analizar")
        self.btn_run.clicked.connect(self.run_analysis)

        self.btn_open_export = QPushButton("Abrir carpeta de exportación")
        self.btn_open_export.clicked.connect(self.open_export_folder)
        self.btn_open_export.setEnabled(False)

        self.btn_save_json = QPushButton("Guardar JSON…")
        self.btn_save_json.clicked.connect(self.save_json)
        self.btn_save_json.setEnabled(False)

        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumBlockCount(2000)
        self.log_box.setFont(QFont("Consolas", 10))

        self.ranges_table = QTableWidget(0, 7)
        self.ranges_table.setHorizontalHeaderLabels([
            "Rango (hex)", "len", "spans", "total_changed",
            "fit", "exported?", "nota"
        ])
        self.ranges_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ranges_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ranges_table.itemSelectionChanged.connect(self.on_range_selected)

        self.spans_table = QTableWidget(0, 6)
        self.spans_table.setHorizontalHeaderLabels([
            "Span (hex)", "len", "orig preview", "signed preview", "orig ctx", "signed ctx"
        ])
        self.spans_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.spans_table.setEditTriggers(QTableWidget.NoEditTriggers)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Original:"))
        top_row.addWidget(self.orig_edit, 1)
        top_row.addWidget(btn_orig)
        top_row.addSpacing(12)
        top_row.addWidget(QLabel("Firmado:"))
        top_row.addWidget(self.signed_edit, 1)
        top_row.addWidget(btn_signed)

        params_box = QGroupBox("Parámetros")
        form = QFormLayout()
        form.addRow("Block size:", self.block_size)
        form.addRow("Contexto hex (bytes):", self.context)
        form.addRow("Known sizes (CSV):", self.profile_edit)
        form.addRow("Fit objetivo (SIZE:COUNT):", self.fit_target)
        form.addRow("Export dir (base):", self.export_dir)

        exp_row = QHBoxLayout()
        exp_row.addWidget(self.chk_export_fit)
        exp_row.addSpacing(12)
        exp_row.addWidget(self.chk_export_big)
        exp_row.addSpacing(12)
        exp_row.addWidget(QLabel("Min blob:"))
        exp_row.addWidget(self.big_blob_min)
        exp_row.addStretch(1)
        form.addRow(exp_row)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.btn_run)
        btn_row.addWidget(self.btn_open_export)
        btn_row.addWidget(self.btn_save_json)
        btn_row.addStretch(1)
        form.addRow(btn_row)
        params_box.setLayout(form)

        left = QWidget()
        left_l = QVBoxLayout(left)
        left_l.addLayout(top_row)
        left_l.addWidget(params_box)
        left_l.addWidget(QLabel("Rangos distintos:"))
        left_l.addWidget(self.ranges_table, 1)

        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.addWidget(QLabel("Spans del rango seleccionado:"))
        right_l.addWidget(self.spans_table, 2)
        right_l.addWidget(QLabel("Log:"))
        right_l.addWidget(self.log_box, 1)

        split = QSplitter(Qt.Horizontal)
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 2)

        central = QWidget()
        main_l = QVBoxLayout(central)
        main_l.addWidget(split)
        self.setCentralWidget(central)

        act_quit = QAction("Salir", self)
        act_quit.triggered.connect(self.close)
        self.menuBar().addMenu("Archivo").addAction(act_quit)

        self.statusBar().showMessage("Listo.")

    def pick_file(self, target_edit: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", "", "All files (*)")
        if path:
            target_edit.setText(path)

    def append_log(self, msg: str):
        self.log_box.appendPlainText(msg)

    def run_analysis(self):
        orig = self.orig_edit.text().strip()
        signed = self.signed_edit.text().strip()
        if not orig or not signed:
            QMessageBox.warning(self, "Faltan archivos", "Selecciona un archivo original y otro firmado.")
            return
        if not os.path.exists(orig) or not os.path.exists(signed):
            QMessageBox.warning(self, "Ruta inválida", "Alguno de los archivos no existe.")
            return

        try:
            known_sizes = parse_sizes_csv(self.profile_edit.text().strip())
            fit_target = parse_fit_target(self.fit_target.text().strip())
        except Exception:
            QMessageBox.warning(self, "Parámetros inválidos", "Revisa 'Known sizes' o 'Fit objetivo'.")
            return

        self.log_box.clear()
        self.append_log("Starting analysis…")

        self.btn_run.setEnabled(False)
        self.btn_open_export.setEnabled(False)
        self.btn_save_json.setEnabled(False)

        self.ranges_table.setRowCount(0)
        self.spans_table.setRowCount(0)
        self.last_report = None
        self.last_export_dir = None
        self.statusBar().showMessage("Analizando… 0%")

        params = dict(
            orig_path=orig,
            signed_path=signed,
            block_size=int(self.block_size.value()),
            context=int(self.context.value()),
            known_sizes=known_sizes,
            fit_target=fit_target,
            export_dir=self.export_dir.text().strip() or "extracted_sigs",
            export_on_fit=self.chk_export_fit.isChecked(),
            export_big_contig=self.chk_export_big.isChecked(),
            big_blob_min=int(self.big_blob_min.value()),
        )

        self.worker = AnalyzeWorker(params)
        self.worker.progress.connect(lambda p: self.statusBar().showMessage(f"Analizando… {p}%"))
        self.worker.log.connect(self.append_log)
        self.worker.finished_ok.connect(self.on_done_ok)
        self.worker.finished_err.connect(self.on_done_err)
        self.worker.start()

    def on_done_ok(self, report: dict):
        self.last_report = report
        self.last_export_dir = report.get("settings", {}).get("export_dir_actual")

        self.btn_run.setEnabled(True)
        self.btn_save_json.setEnabled(True)
        self.btn_open_export.setEnabled(bool(self.last_export_dir and os.path.isdir(self.last_export_dir)))

        self.statusBar().showMessage("Listo.")
        self.append_log(f"Exports: {len(report.get('exports', []))}")
        if self.last_export_dir:
            self.append_log(f"Export dir: {self.last_export_dir}")

        self.populate_ranges(report)

    def on_done_err(self, err: str):
        self.btn_run.setEnabled(True)
        self.btn_open_export.setEnabled(False)
        self.btn_save_json.setEnabled(False)
        self.statusBar().showMessage("Error.")
        self.append_log(err)
        QMessageBox.critical(self, "Error durante el análisis", err)

    def open_export_folder(self):
        if self.last_export_dir and os.path.isdir(self.last_export_dir):
            os.startfile(self.last_export_dir)  # Windows
        else:
            QMessageBox.information(self, "Sin carpeta", "No hay carpeta de exportación disponible.")

    def populate_ranges(self, report: dict):
        rows = report["diff"]["ranges_detail"]
        self.ranges_table.setRowCount(len(rows))

        for i, r in enumerate(rows):
            rs, re = r["range_start"], r["range_end"]
            fit = r.get("size_fit")
            fit_s = fit_to_str(fit) if fit else ""

            exported_count = len(r.get("exported_files", []))
            exported = "yes" if exported_count > 0 else "no"

            if fit:
                note = "Encaja con tamaños conocidos"
            else:
                note = "Sin fit (posible metadata/estructura o firma no modelada)"

            self.ranges_table.setItem(i, 0, QTableWidgetItem(f"0x{rs:08X}..0x{re:08X}"))
            self.ranges_table.setItem(i, 1, QTableWidgetItem(str(r["range_len"])))
            self.ranges_table.setItem(i, 2, QTableWidgetItem(str(r["num_spans"])))
            self.ranges_table.setItem(i, 3, QTableWidgetItem(str(r["total_changed_bytes_in_range"])))
            self.ranges_table.setItem(i, 4, QTableWidgetItem(fit_s))
            self.ranges_table.setItem(i, 5, QTableWidgetItem(f"{exported} ({exported_count})"))
            self.ranges_table.setItem(i, 6, QTableWidgetItem(note))

        self.ranges_table.resizeColumnsToContents()
        # Estira la última columna (nota) para mejor lectura
        header = self.ranges_table.horizontalHeader()
        header.setStretchLastSection(True)

    def on_range_selected(self):
        if not self.last_report:
            return
        sel = self.ranges_table.selectedItems()
        if not sel:
            return
        row = sel[0].row()
        r = self.last_report["diff"]["ranges_detail"][row]
        spans = r.get("spans", [])
        self.spans_table.setRowCount(len(spans))
        for i, sp in enumerate(spans):
            s, e = sp["start"], sp["end"]
            self.spans_table.setItem(i, 0, QTableWidgetItem(f"0x{s:08X}..0x{e:08X}"))
            self.spans_table.setItem(i, 1, QTableWidgetItem(str(sp["length"])))
            self.spans_table.setItem(i, 2, QTableWidgetItem(sp["orig_preview_hex"]))
            self.spans_table.setItem(i, 3, QTableWidgetItem(sp["signed_preview_hex"]))
            self.spans_table.setItem(i, 4, QTableWidgetItem(sp["orig_context_hex"]))
            self.spans_table.setItem(i, 5, QTableWidgetItem(sp["signed_context_hex"]))
        self.spans_table.resizeColumnsToContents()

    def save_json(self):
        if not self.last_report:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar JSON", "firmware_report.json", "JSON (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.last_report, f, indent=2)
        self.statusBar().showMessage(f"Guardado: {path}")

def main():
    app = QApplication([])
    w = MainWindow()
    w.show()
    app.exec()

if __name__ == "__main__":
    main()
