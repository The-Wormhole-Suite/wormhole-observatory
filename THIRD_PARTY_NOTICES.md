# Third-party notices

Wormhole Observatory is licensed under AGPL-3.0-only. Components listed below
remain under their own licenses. Nothing in the Wormhole Observatory license
relicenses third-party code.

## Embedded source: sbarbett/pihole6api

The `pihole6api/` package is derived from:

- Project: `sbarbett/pihole6api`
- Source: https://github.com/sbarbett/pihole6api
- License: MIT

Original license notice:

> Copyright 2025 Shane Barbetta
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## Python dependencies in binary distributions

Windows and Linux Onedir releases are built from the exact versions pinned in
`requirements-build.lock`. The release build deterministically collects license,
copyright, copying, and notice files shipped by those installed Python
distributions into `THIRD_PARTY_LICENSES.txt` inside the final application ZIP.

That generated bundle is release-gated: packaging fails if a pinned distribution
cannot be resolved or if the mandatory Wormhole Observatory legal files are
missing from the Onedir tree.
