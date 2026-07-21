# Build the Task 2 report

```bash
mkdir -p ../tmp/pdfs ../output/pdf
latexmk -xelatex -interaction=nonstopmode -halt-on-error -outdir=../tmp/pdfs task2.tex
cp ../tmp/pdfs/task2.pdf ../output/pdf/task2_secp256k1_report.pdf
```

After compilation, run `pdfinfo`, render every page with `pdftoppm`, and inspect the PNG files before delivery.

