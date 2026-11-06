# PDF Hidden Text Scanner and Remover

These two Python scripts help review PDF files for suspicious or hidden text that could contain prompt-injection instructions. The scanner identifies and reports suspicious content. The remover creates a separate cleaned copy of the PDF after you choose which findings to remove.

> **Important:** These tools are for inspection and cleanup assistance. Their detection is heuristic, not a guarantee that a PDF is safe or unsafe. Review flagged text in the original PDF before deciding what to remove. Keep an untouched backup of important PDFs.

## Contents

- [1. What you need](#1-what-you-need)
- [2. Put the files together](#2-put-the-files-together)
- [3. Install Python](#3-install-python)
- [4. Create an environment and install Python packages](#4-create-an-environment-and-install-python-packages)
- [5. Install optional Tesseract OCR](#5-install-optional-tesseract-ocr)
- [6. Verify the setup](#6-verify-the-setup)
- [7. Use the PDF scanner](#7-use-the-pdf-scanner)
- [8. Use the PDF remover](#8-use-the-pdf-remover)
- [9. How the scripts work](#9-how-the-scripts-work)
- [10. Troubleshooting](#10-troubleshooting)

## 1. What you need

Required:

- Python 3.11 or newer is recommended.
- The two Python scripts:
  - `pdf_hidden_text_scanner.py`
  - `pdf_remove_hidden_text.py`
- The following Python packages:
  - `pymupdf`
  - `numpy`
  - `pillow`

Optional:

- Tesseract OCR and its language data. This enables the scanner's OCR comparison checks. The scripts can still run without Tesseract, but OCR-based checks will not be available.

You do **not** need to install `pytesseract`. PyMuPDF provides the OCR interface used by these scripts; Tesseract and its language data are installed separately when OCR is wanted.

## 2. Put the files together

Create a folder for the tools. For example:

```text
PDF-Hidden-Text-Tools/
├── pdf_hidden_text_scanner.py
├── pdf_remove_hidden_text.py
└── PDFs/
    └── example.pdf
```

Keep `pdf_hidden_text_scanner.py` and the remover in the **same folder**. The remover imports the scanner using this exact module filename, so do not rename `pdf_hidden_text_scanner.py` unless you also update the import inside the remover.

Keep the remover named `pdf_remove_hidden_text.py` so the commands in this README work as written. The remover can be renamed, but you would then need to use its new filename in your terminal commands.

The PDF files can be stored in this folder, in the example `PDFs` subfolder, or somewhere else. You will provide the PDF path when you run a script.

## 3. Install Python

### Windows

1. Open the official [Python downloads page](https://www.python.org/downloads/).
2. Download and run a current Python 3 installer.
3. During installation, enable **Add Python to PATH** if that option is shown.
4. Finish the installation.
5. Open a **new** PowerShell window and verify Python is available:

   ```powershell
   py --version
   ```

   You should see a Python 3 version number. If `py` is unavailable, try:

   ```powershell
   python --version
   ```

### macOS or Linux

Install a current Python 3 release using the operating system's package manager or the installer provided by [python.org](https://www.python.org/downloads/). Open a new terminal and verify:

```bash
python3 --version
```

## 4. Create an environment and install Python packages

A virtual environment keeps the packages for these scripts separate from other Python projects. This is recommended, but not strictly required.

### Windows PowerShell

1. Change to the folder containing the two scripts. For example:

   ```powershell
   cd "$HOME\Documents\PDF-Hidden-Text-Tools"
   ```

   Change the path to wherever you saved the folder.

2. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

3. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks the activation script, you can allow scripts for this PowerShell window only, then activate again:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\.venv\Scripts\Activate.ps1
   ```

4. Update pip:

   ```powershell
   python -m pip install --upgrade pip
   ```

5. Install all required Python packages:

   ```powershell
   python -m pip install --upgrade pymupdf numpy pillow
   ```

### macOS or Linux

Open a terminal, change to the folder containing the scripts, and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --upgrade pymupdf numpy pillow
```

When the virtual environment is active, your terminal prompt will usually show `(.venv)`. Any time you open a new terminal to use the tools, change to the project folder and activate the environment again.

To leave the virtual environment, run:

```bash
deactivate
```

## 5. Install optional Tesseract OCR

Tesseract is optional. Install it to enable the scanner's OCR comparison, which checks whether extracted PDF text can also be found in the rendered page image.

### Windows

1. Open the [Tesseract at UB Mannheim installation page](https://github.com/UB-Mannheim/tesseract/wiki).
2. Download the current 64-bit Windows installer.
3. Run the installer. Make sure the English language data is included. The usual installation folder is:

   ```text
   C:\Program Files\Tesseract-OCR
   ```

4. Add the Tesseract installation folder to your Windows `Path` environment variable if it is not already there. The folder is normally:

   ```text
   C:\Program Files\Tesseract-OCR
   ```

   This lets you verify the installation using the `tesseract` command.

5. Set `TESSDATA_PREFIX` to the folder containing the Tesseract language data. The usual English-data folder is:

   ```text
   C:\Program Files\Tesseract-OCR\tessdata
   ```

   You can set it permanently for your Windows user by running this in PowerShell:

   ```powershell
   [Environment]::SetEnvironmentVariable("TESSDATA_PREFIX", "C:\Program Files\Tesseract-OCR\tessdata", "User")
   ```

6. Close and reopen PowerShell so it receives the updated environment variables.

7. Verify the installation:

   ```powershell
   tesseract --version
   Test-Path "$env:TESSDATA_PREFIX\eng.traineddata"
   ```

   The first command should print the Tesseract version. The second should return `True` if the English language data is at the configured location.

### macOS

With [Homebrew](https://brew.sh/) installed, run:

```bash
brew install tesseract
```

Check the installation details and language-data location with:

```bash
brew info tesseract
```

If needed, set `TESSDATA_PREFIX` to the `tessdata` directory shown by Homebrew. For example, a common Homebrew location is:

```bash
export TESSDATA_PREFIX="$(brew --prefix)/share/tessdata"
```

To make that setting persistent in the usual zsh shell, add the export line to `~/.zshrc`, then open a new terminal or run `source ~/.zshrc`.

### Ubuntu or Debian Linux

Install Tesseract using the system package manager:

```bash
sudo apt update
sudo apt install tesseract-ocr
```

Locate the English language-data file:

```bash
find /usr/share -type f -name eng.traineddata 2>/dev/null
```

Set `TESSDATA_PREFIX` to the directory containing `eng.traineddata`. For example, if the file is in `/usr/share/tesseract-ocr/5/tessdata/eng.traineddata`, run:

```bash
export TESSDATA_PREFIX="/usr/share/tesseract-ocr/5/tessdata"
```

The exact directory can vary by Linux distribution and installed Tesseract version. Add the correct export command to your shell profile if you want it to persist across terminal sessions.

### Additional OCR languages

The default OCR language is English (`eng`). To use another language, install that language's Tesseract data file and provide its language code when running a script. For example, `eng+fra` requests English and French. The required language data must exist in the configured `tessdata` directory.

PyMuPDF's installation guide has additional details about OCR and the `TESSDATA_PREFIX` setting: [PyMuPDF installation and OCR instructions](https://pymupdf.readthedocs.io/en/latest/installation.html). Tesseract's platform installation information is available in the [official Tesseract documentation](https://tesseract-ocr.github.io/tessdoc/Installation.html).

## 6. Verify the setup

Make sure the virtual environment is active, then run this command from the folder containing the scripts.

### Verify the Python packages

```powershell
python -c "import pymupdf, numpy, PIL; print('All required Python packages are installed.')"
```

On macOS or Linux, use the same command after activating the virtual environment.

### Verify that the scripts start

```powershell
python pdf_hidden_text_scanner.py --help
python pdf_remove_hidden_text.py --help
```

Each command should display its usage instructions. If either command reports a missing Python module, activate the virtual environment and repeat the package-installation step.

## 7. Use the PDF scanner

The scanner checks a PDF and displays suspicious findings in the terminal. When findings exist, it also creates a detailed text report unless you choose to preserve an existing report.

1. Open PowerShell or a terminal.
2. Change to the tools folder.
3. Activate the virtual environment if you created one.
4. Run the scanner and provide the PDF path. For example:

   ```powershell
   python pdf_hidden_text_scanner.py ".\PDFs\example.pdf"
   ```

5. Review the terminal output. Each finding includes a finding number, page number, reason(s), and a copy-ready line containing the flagged text. The document risk score and suspicious span percentage are shown below the findings.
6. If suspicious findings were detected, look for the generated report beside the PDF. The default name is:

   ```text
   example_hidden_text_report.txt
   ```

   The report contains detailed findings, reasons, page numbers, flagged text, and supporting details such as text opacity, text colour, estimated background colour, background uniformity, text size, and the document's median font size.

### Scanner options

**Choose a different TXT report path:**

```powershell
python pdf_hidden_text_scanner.py ".\PDFs\example.pdf" --output ".\PDFs\review\example_review.txt"
```

**Also create a JSON report:**

```powershell
python pdf_hidden_text_scanner.py ".\PDFs\example.pdf" --report-json ".\PDFs\example_findings.json"
```

**Disable OCR:**

```powershell
python pdf_hidden_text_scanner.py ".\PDFs\example.pdf" --no-ocr
```

Use `--no-ocr` when Tesseract is not installed, when OCR is not needed, or when you want to avoid the additional OCR processing. The scanner's other checks still run.

**Use a different OCR language:**

```powershell
python pdf_hidden_text_scanner.py ".\PDFs\example.pdf" --ocr-language eng+fra
```

This requires the requested Tesseract language data to be installed.

**Overwrite an existing TXT report without being prompted:**

```powershell
python pdf_hidden_text_scanner.py ".\PDFs\example.pdf" --overwrite
```

### Existing report behaviour

If the default TXT report (or the path supplied with `--output`) already exists, the scanner asks whether you want to overwrite it:

```text
Do you want to overwrite it? [y/N]:
```

- Enter `y` or `yes` to replace the report.
- Press Enter, or enter anything other than `y` or `yes`, to keep the existing report.

Choosing **No** does not cancel the scan. The scanner still prints the findings and both metrics in the terminal, but it does not write a new TXT report at that path. The existing report is left unchanged. Use `--overwrite` to skip the prompt and replace the TXT report.

The TXT report is normally created only when findings are detected. If you approve overwriting an existing TXT report and the new scan finds nothing, the old report is removed so it is not mistaken for the result of the new scan.

## 8. Use the PDF remover

The remover runs the scanner's analysis, displays findings in the same terminal layout, and asks which findings to remove. It also looks for recurring headers and footers.

1. Make sure both scripts are in the same folder and the virtual environment is active.
2. Run the remover with the PDF path. For example:

   ```powershell
   python pdf_remove_hidden_text.py ".\PDFs\example.pdf"
   ```

3. Review the findings and the two metrics printed below them.
4. At the selection prompt, choose what to remove:

   | Input | Action |
   |---|---|
   | Press Enter | Remove all scanner findings that the remover supports removing |
   | `in 1,2,4` | Remove only findings 1, 2, and 4 |
   | `ex 3,4` | Remove all findings except 3 and 4 |
   | `q` | Cancel without creating a cleaned PDF |

   Finding numbers correspond to the numbered findings displayed in the terminal. Separate multiple numbers with commas.

5. The cleaned copy is saved beside the original PDF using this filename pattern:

   ```text
   example_cleaned.pdf
   ```

6. Open the cleaned PDF and check the pages to confirm that the intended content was removed and that nearby visible content is still correct.

If a cleaned output with that name already exists, the remover asks whether to overwrite it. Enter `y` or `yes` to replace it. Press Enter or enter anything else to cancel; the default is No.

### Remover options

**Disable OCR during the scan:**

```powershell
python pdf_remove_hidden_text.py ".\PDFs\example.pdf" --no-ocr
```

**Use a different OCR language:**

```powershell
python pdf_remove_hidden_text.py ".\PDFs\example.pdf" --ocr-language eng+fra
```

As with the scanner, the requested Tesseract language data must be installed. The remover does not have a command-line `--overwrite` option; it asks before replacing an existing cleaned PDF.

### Important remover limitations

- The remover applies PDF redactions to findings that are ordinary page-text spans and have a usable text bounding box. The scanner can also identify text in annotations/comments and form fields, but the current remover does **not** delete those underlying annotation or form-field objects. Selecting one of those findings does not remove that object.
- Recurring header/footer text is detected separately and removed automatically, regardless of the finding selection. The heuristic looks for matching text spans in the top or bottom 12% of pages and requires the text to recur on at least 60% of pages, with a minimum of two pages.
- Header/footer removal is heuristic. It may miss headers or footers that change from page to page, and it can mistake repeated content near a page edge for a header or footer. Review the cleaned PDF carefully.
- Redaction rectangles are based on PDF text coordinates. Text close to a flagged span may be affected if it overlaps the redaction rectangle.
- The original PDF is not overwritten. The remover writes a separate `_cleaned.pdf` file.
- The remover's final selected-finding count is the number of findings you chose; it is not proof that every selected finding was physically removed. In particular, annotation/comment and form-field objects are not deleted by the current implementation.

## 9. How the scripts work

### `pdf_hidden_text_scanner.py`

The scanner opens the PDF with PyMuPDF and examines its text and page structure. It gathers ordinary page-text spans and also checks separate PDF text locations such as annotations/comments and form fields. It can inspect hidden optional-content layers by examining a temporary copy with layers enabled.

For ordinary page text, it combines several kinds of evidence, including:

- Text drawn using an invisible rendering mode or zero/near-zero opacity.
- Text whose colour closely matches the local page background.
- Very small text, including extremely small text and text unusually small compared with the document's median font size.
- Text covered by a later page object or positioned mostly outside the page boundaries.
- Text that appears in a hidden optional-content layer, annotation/comment, or form field.
- Invisible or directional Unicode formatting characters.
- Wording patterns that resemble prompt-injection instructions, such as attempts to override previous instructions, change an AI assistant's role, suppress a response, or reveal hidden instructions. The pattern list includes English and Chinese examples.
- Differences between embedded PDF text and OCR text recognized from the rendered page, when OCR is available.

Each finding receives a heuristic score based on the evidence signals that apply to it. The **Document risk score** is the highest individual finding score in the document; it is not a calibrated probability that the PDF is malicious. The **Suspicious span percentage** is the number of flagged text units divided by the total extracted text units, expressed as a percentage. It is a measure of how many extracted units were flagged, not the percentage of page area or characters that are suspicious.

The scanner prints a bordered findings table and copy-ready flagged text in the terminal. When findings exist and report writing is enabled, it also writes a detailed TXT report. A JSON report can be requested separately with `--report-json`. The source PDF is not modified.

### `pdf_remove_hidden_text.py`

The remover imports `pdf_hidden_text_scanner.py` and calls its analysis function, so it uses the same detection logic, finding order, and terminal findings formatter. It uses a temporary directory for the scanner's intermediate TXT report and removes that temporary directory after analysis; it does not create a persistent scanner TXT report.

After displaying the findings and metrics, it interprets your selection. For supported page-text findings, it uses the finding's bounding box to place a PDF redaction annotation and applies the redaction to the output document. It separately detects recurring header/footer spans using the page-edge and repetition heuristic described above, then redacts those spans as well.

Finally, it saves the modified document as a new `_cleaned.pdf` file. The original PDF remains unchanged. Because some scanner findings refer to PDF objects rather than ordinary page text, the remover's current redaction support is narrower than the scanner's detection support; see [Important remover limitations](#important-remover-limitations) before relying on the cleaned file.

## 10. Troubleshooting

### `python` or `py` is not recognized

Python may not have been added to `Path`, or the terminal may have been open during installation. Re-run the Python installer with the PATH option enabled, then close and reopen the terminal. On Windows, try `py --version`; on macOS/Linux, try `python3 --version`.

### `ModuleNotFoundError` for `pymupdf`, `numpy`, or `PIL`

Activate the virtual environment for this project and run:

```powershell
python -m pip install --upgrade pymupdf numpy pillow
```

Use `python -m pip` from the same Python environment that you use to run the scripts.

### OCR does not appear to run

1. Confirm that Tesseract is installed.
2. Confirm that the `tessdata` directory contains `eng.traineddata` (or the data file for the language you selected).
3. Confirm that `TESSDATA_PREFIX` points to the directory containing the `.traineddata` files.
4. On Windows, close and reopen PowerShell after changing environment variables.
5. Try `tesseract --version` to verify the Tesseract command is available.

The scripts can still run without OCR. Use `--no-ocr` to disable OCR explicitly.

### The remover cannot find the scanner module

Make sure `pdf_hidden_text_scanner.py` is in the same folder as the remover and that its filename has not been changed. Also make sure you run the remover with the correct Python environment activated.

### A report or cleaned PDF already exists

The scanner and remover protect existing output files by asking before replacing them. Read the prompt carefully. For the scanner, `--overwrite` skips the TXT report prompt. The remover always asks before replacing an existing cleaned PDF.

### The cleaned PDF still contains a flagged item

The remover currently applies redactions only to supported page-text findings. Annotation/comment and form-field objects are not removed by the current implementation. Also check whether the finding was excluded by your selection, and whether the text is part of a repeated header/footer or another PDF object that the remover does not handle.

---

## Reference documentation

- [Python downloads](https://www.python.org/downloads/)
- [PyMuPDF installation and OCR documentation](https://pymupdf.readthedocs.io/en/latest/installation.html)
- [Official Tesseract installation documentation](https://tesseract-ocr.github.io/tessdoc/Installation.html)
- [Tesseract Windows installers (UB Mannheim)](https://github.com/UB-Mannheim/tesseract/wiki)
