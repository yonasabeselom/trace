# Changelog

All notable changes to TRACE are documented here.

---

## [1.0] — 2026-08-07

### Initial Release

- 100 forensic artifacts across HIGH / MEDIUM / LOW tiers
  - 70 HIGH-risk artifacts (weight 3)
  - 20 MEDIUM-risk artifacts (weight 2)
  - 10 LOW-risk artifacts (weight 1)
- Weighted exposure score (0–100)
- Real-time colour-coded terminal output
- PDF report export via `reportlab`
  - Professional cover page with score
  - Full artifact results table
  - Tier breakdown summary
- Auto-elevation to Administrator
- Press Y to save PDF, N to exit without saving
- Desktop auto-save for PDF report
- Full abbreviation: **T**otal **R**isk **A**ssessment & **C**omputed **E**xposure
- Links to REDACT and AAD-50 in PDF and terminal
