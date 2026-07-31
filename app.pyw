from __future__ import annotations

import traceback


def _show_startup_error(message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Pi-hole Manager startup error", message, parent=root)
        root.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        from pihole_manager.__main__ import main

        raise SystemExit(main())
    except ModuleNotFoundError as exc:
        package = exc.name or "an unknown package"
        _show_startup_error(
            f"A required Python package is missing: {package}\n\n"
            "Install the project dependencies once with:\n"
            "python -m pip install -e .\n\n"
            "A packaged Windows executable will include these dependencies automatically."
        )
        raise SystemExit(1) from exc
    except Exception as exc:
        _show_startup_error(
            f"Pi-hole Manager could not start:\n\n{exc}\n\n"
            "See pihole_manager.log for additional details when logging was initialized."
        )
        traceback.print_exc()
        raise SystemExit(1) from exc
