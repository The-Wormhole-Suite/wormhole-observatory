"""Single-file entry point for the Pi-hole Manager GUI.
You can either:
- run `python app.py` (this file), or
- `python -m gui` if we made gui runnable.

We keep `app.py` as a tiny, explicit entry point so you can double-click it on Windows.
"""
from gui import run_app

if __name__ == "__main__":
    run_app()
