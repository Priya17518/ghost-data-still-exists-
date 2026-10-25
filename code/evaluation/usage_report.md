# Usage report

## Full-dataset run

- Input: `dataset/deletion_requests.csv` — 518 requests.
- Output: `output.csv` — 518 rows.
- Runtime: Python 3.12.10; local execution completed in 16.48 seconds.
- Providers/models invoked by the audit program: none. The run uses local Python code and participant-facing files; it makes no model or external API calls.
- Coding-session runtime: GitHub Copilot / `gpt-6-luna`, confirmed from the session trace. This model supported solution development; it was not invoked by the full-dataset audit job.

## Usage totals

| Measure | Per request | Total |
|---|---:|---:|
| Model calls | 0 | 0 |
| Input tokens | 0 | 0 |
| Output tokens | 0 | 0 |
| Total tokens | 0 | 0 |
| Estimated model/API cost | $0.00 | $0.00 |

The average token usage is 0 per request across all 518 requests. Authoring-session assistant usage is not attributed to the dataset-processing run. The cost figure covers model/API usage by the audit program, not any bundled IDE or subscription fees.

## Output summary

- `COMPLETE`: 156
- `INCOMPLETE`: 355
- `NOT_APPLICABLE`: 7
- Output contract validation errors: 0

`INCOMPLETE` cases include unresolved or insufficient evidence; the program reports evidence limitations rather than claiming an unsupported deletion state. The full run emitted 37 evidence/audit limitation warnings, including 11 image files that require OCR.

## Reproduction Commands

Execute the workflow with standard Python (prefer `.\.venv\Scripts\python.exe` when virtual environment is present):

1. **Generate sample predictions**:
   ```powershell
   python code/main.py --input dataset/sample_deletion_requests.csv --output sample_prediction.csv
   ```
2. **Evaluate sample predictions and run unit tests**:
   ```powershell
   python code/evaluation/main.py --actual sample_prediction.csv
   ```
3. **Generate official full-dataset audit output**:
   ```powershell
   python code/main.py --input dataset/deletion_requests.csv --output output.csv
   ```
4. **Validate output contract and Case ID coverage**:
   ```powershell
   python code/evaluation/main.py --actual sample_prediction.csv
   ```
5. **Package submission archive**:
   ```powershell
   python -c "import zipfile, os; zf = zipfile.ZipFile('code.zip', 'w', zipfile.ZIP_DEFLATED); [zf.write(os.path.join(r, f), os.path.join(r, f).replace('\\\\', '/')) for r, d, fs in os.walk('code') if '__pycache__' not in r for f in fs if not f.endswith(('.pyc', '.tmp'))]; [zf.write(f, f) for f in ('README.md', 'AGENTS.md', 'problem_statement.md') if os.path.exists(f)]; [zf.write(os.path.join('code', 'evaluation', f), f'evaluation/{f}') for f in ('evaluation_report.md', 'usage_report.md')]; zf.close()"
   ```
