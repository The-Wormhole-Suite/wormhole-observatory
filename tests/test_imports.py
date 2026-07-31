from __future__ import annotations


def test_public_modules_import() -> None:
    import pihole6api  # noqa: F401
    import pihole_manager.config  # noqa: F401
    import pihole_manager.database  # noqa: F401
    import pihole_manager.gui.app  # noqa: F401
    import pihole_manager.gui.evidence_dialog  # noqa: F401
    import pihole_manager.gui.tabs.domains  # noqa: F401
    import pihole_manager.gui.tree_sorting  # noqa: F401
    import pihole_manager.llm  # noqa: F401
    import pihole_manager.research  # noqa: F401
    import pihole_manager.updater  # noqa: F401
    import pihole_manager.workers  # noqa: F401
