# Contributing

Contributions are welcome. Please follow these guidelines.

## Getting started

```bash
git clone https://github.com/nikolareljin/claude-reposec
cd claude-reposec
python -m venv venv && source venv/bin/activate
pip install -e .
pytest tests/ -v
```

## Pull requests

- Fork the repository and create a feature branch
- Write tests for any new scanner patterns or functionality
- Ensure all tests pass: `pytest tests/ -v`
- Keep PRs focused — one feature or fix per PR
- Reference any related issues in the PR description

## Adding scanner patterns

New detection patterns go in the appropriate module under `src/claude_reposec/`.
Add at least one positive and one negative test case in `tests/`.

## Code style

- PEP 8, 4-space indents, type hints
- Run `python -m py_compile src/claude_reposec/*.py` before submitting
