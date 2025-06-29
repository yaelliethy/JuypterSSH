# Contributing to JuypterSSH

Thanks for your interest in improving JuypterSSH!  We welcome PRs, bug reports and feature ideas.

---

## 🧑‍💻  Development setup
1. Fork & clone this repo.  
2. `python -m venv .venv && source .venv/bin/activate`  
3. `pip install -r requirements.txt -r dev-requirements.txt` (dev-requirements listed below).
4. Start the server against a local Jupyter (`jupyter lab --no-browser`) and iterate.

### dev-requirements.txt
```
black
ruff
pre-commit
```
Install hooks: `pre-commit install`.

---

## 📐  Coding style
* **Black** formatting (`black .`).  
* **Ruff** for linting (`ruff .`).  
* Type-hints encouraged; CI runs `mypy` in strict mode.

---

## 🔀  Pull-request process
1. Create a feature branch (`feat/my-thing`).
2. Ensure `black`, `ruff`, `mypy` are clean.
3. Open PR against `main` with a concise description.
4. One approval + passing CI → merge via squash-and-merge.

Small, focused PRs are easier to review than huge ones.

---

## 🐞  Reporting bugs
* Include **steps to reproduce**, expected vs. actual behaviour and logs (`JUYPTERSSH_DEBUG=1`).
* If the issue is security-sensitive, email the maintainer privately.

---

## 🎯  Roadmap / Good first issues
See [GitHub issues](../../issues) labelled `good first issue` or `help wanted`.

---

## 📜  License & CLA
By submitting a PR you agree that your work will be released under the project's MIT license. 
