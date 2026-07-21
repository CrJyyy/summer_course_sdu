# Build the Task 1 report

```bash
mkdir -p ../tmp/pdfs ../output/pdf
latexmk -xelatex -interaction=nonstopmode -halt-on-error -outdir=../tmp/pdfs task1.tex
cp ../tmp/pdfs/task1.pdf ../output/pdf/task1_testnet4_tx_block.pdf
```

After compilation, run `pdfinfo`, render every page with `pdftoppm`, and inspect the PNG files before delivery.

