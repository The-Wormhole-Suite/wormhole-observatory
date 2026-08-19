from __future__ import annotations

import threading

import pytest

from pihole_manager.cancellation import CancellationToken, OperationCancelledError
from pihole_manager.database import (
    analysis_run_finish,
    analysis_run_get,
    analysis_run_start,
    init_db,
)


def test_cancellation_token_honors_local_and_parent_events() -> None:
    parent = threading.Event()
    token = CancellationToken(parent)
    assert not token.is_set()
    parent.set()
    assert token.is_set()
    with pytest.raises(OperationCancelledError):
        token.raise_if_cancelled()
    local = CancellationToken()
    local.cancel()
    assert local.is_set()


def test_research_rejects_pre_cancelled_job_before_loading_options(monkeypatch) -> None:
    import pihole_manager.research as research
    token = CancellationToken()
    token.cancel()

    def unexpected_load():
        raise AssertionError('configuration must not be loaded after cancellation')

    monkeypatch.setattr(research, 'load_options', unexpected_load)
    with pytest.raises(OperationCancelledError):
        research.research_many(['example.com'], cancel_token=token)


def test_dispatch_rejects_pre_cancelled_job_before_loading_options(monkeypatch) -> None:
    import pihole_manager.analysis_dispatcher as dispatcher
    token = CancellationToken()
    token.cancel()

    def unexpected_load():
        raise AssertionError('configuration must not be loaded after cancellation')

    monkeypatch.setattr(dispatcher, 'load_options', unexpected_load)
    with pytest.raises(OperationCancelledError):
        dispatcher.dispatch_analysis(
            'background',
            ['example.com'],
            [{'domain': 'example.com'}],
            cancel_token=token,
        )


def test_cancelled_analysis_run_is_persisted(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv('PIHOLE_MANAGER_HOME', str(tmp_path))
    init_db()
    run_id = analysis_run_start('background', 'fallback', source='test')
    analysis_run_finish(run_id, status='cancelled', error='user cancelled')
    row = analysis_run_get(run_id)
    assert row is not None
    assert row['status'] == 'cancelled'
    assert row['error'] == 'user cancelled'
