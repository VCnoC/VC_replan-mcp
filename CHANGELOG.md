# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8] - 2026-03-01

### Added
- **CLI Raw Output Support**: Added CLI raw output fields to `IntelligenceSources` schema
  - `kb_cli_raw_output`: Raw stdout from CLI execution (for debugging)
  - `kb_cli_stderr`: Raw stderr from CLI execution (for debugging)
  - `kb_cli_metadata`: Additional CLI execution metadata (duration, return code, etc.)
- Enhanced debugging capabilities for clink CLI integration
- Full transparency of CLI execution process and reasoning

### Changed
- Updated `KBRetrievalResult` dataclass to include CLI raw output fields
- Modified `_retrieve_via_clink()` to capture and store raw CLI output
- Enhanced `audit.py` to pass CLI raw output to final response

### Technical Details
- CLI output is now fully preserved in the audit response
- Users can inspect the complete CLI reasoning process and output
- Metadata includes execution duration, return code, and parsed content length

## [0.1.7] - 2026-02-28

### Initial Release
- 7-dimension architecture review matrix
- Knowledge base integration with clink CLI
- Web intelligence gathering via unifuncs API
- Sanitization and security validation
- Structured vulnerability reporting
