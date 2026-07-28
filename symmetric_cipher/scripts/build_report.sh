#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$root/tmp/pdfs" "$root/tmp/matplotlib" "$root/tmp/fontconfig" \
  "$root/results/figures" "$root/output/pdf"

MPLCONFIGDIR="$root/tmp/matplotlib" \
XDG_CACHE_HOME="$root/tmp/fontconfig" \
python3 "$root/scripts/plot_results.py"
if [ -f "$root/results/summary/x86_summary.json" ]; then
  python3 "$root/scripts/plot_results.py" \
    --input "$root/results/summary/x86_summary.json" --prefix x86_
fi
python3 "$root/scripts/generate_report_data.py"

cd "$root"
latexmk -xelatex -interaction=nonstopmode -halt-on-error \
  -outdir=tmp/pdfs report/report.tex
cp tmp/pdfs/report.pdf output/pdf/symmetric_cipher_software_optimization.pdf

pdfinfo output/pdf/symmetric_cipher_software_optimization.pdf \
  > tmp/pdfs/pdfinfo.txt
mkdir -p tmp/pdfs/rendered
pdftoppm -png -r 120 output/pdf/symmetric_cipher_software_optimization.pdf \
  tmp/pdfs/rendered/page >/dev/null 2>&1
printf '%s\n' "Built output/pdf/symmetric_cipher_software_optimization.pdf"
