# Contributing Guide

Thanks for considering contributing to the XRd tools project!

Please have a read through this guide before submitting issues or pull requests, but otherwise we welcome constructive feedback and improvements!


## Creating Issues

We use GitHub issues to track public bugs.
Report a bug or submit a feature request by [opening a new issue](https://github.com/ios-xr/xrd-tools/issues/new).

Please note that unfortunately we may not be able to accept all feature requests due to time constraints within the team.
Be sure to create an issue before submitting a PR so that we can give feedback to avoid any time being wasted if we're unable to accept a change.

Please include the following in a bug report where possible:
- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happened
- Log and version output
  - Output from `docker logs <ctr>` (or equivalent).
  - Output of `docker version` (or equivalent).
  - Output from `uname -a`.
- Extra notes
  - E.g. why you think this might be happening, or stuff you tried that didn't work


## Submitting PRs

PRs are happily accepted as long as the change has been agreed with maintainers beforehand.
This should be done by creating an issue (see above) and stating the intention to implement the change.

Agreeing changes before diving in helps to ensure everyone's happy with the changes and gives a chance for any required discussion to take place!


### Tests and Linting

All tests and checks will be automatically run in a PR via GitHub actions, but it is advisable to get them all passing manually before raising a PR.

The following checks should be run:
- [Shellcheck](https://www.shellcheck.net/) (for bash code)
- [Pylint](https://pylint.pycqa.org/) (for python code)
- [Mypy](https://mypy.readthedocs.io/) (for python code)
- [Black](https://black.readthedocs.io/) and [isort](https://pycqa.github.io/isort/) formatting (for python code)
- [Pytest](https://docs.pytest.org/): `pytest tests/`

Install the python dependencies (and shellcheck) using a venv and the `requirements.txt` file:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

For convenience all of the above can be run using the `commit-check` script, although running each check individually will give faster turnaround for diagnosing individual failures!

Any python code changes should include full code coverage or justification for why this is not required.
Coverage can be checked using the `pytest-cov` plugin:  
`pytest tests/ --cov scripts/`


### Coding Style

Python code should be formatted using [`black`](https://black.readthedocs.io/) - this will be checked by a GitHub action and will block merging PRs.


## License

By contributing, you agree that your contributions will be licensed under the [Apache License](LICENSE) that covers the project.
