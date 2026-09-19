from freshness import (
    check_freshness,
    save_freshness_state,
    load_freshness_state,
    remove_freshness_state
)


def test_first_share_is_accepted():
    state = {}

    result = check_freshness(
        state,
        b"alice",
        b"document1",
        1,
        1000
    )

    assert result is True


def test_newer_sequence_is_accepted():
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        1,
        1000
    )

    result = check_freshness(
        state,
        b"alice",
        b"document1",
        2,
        1001
    )

    assert result is True


def test_replayed_share_is_rejected():
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        1,
        1000
    )

    result = check_freshness(
        state,
        b"alice",
        b"document1",
        1,
        1000
    )

    assert result is False


def test_old_sequence_is_rejected():
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        5,
        1000
    )

    result = check_freshness(
        state,
        b"alice",
        b"document1",
        3,
        1001
    )

    assert result is False


def test_timestamp_cannot_go_backwards():
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        1,
        1000
    )

    result = check_freshness(
        state,
        b"alice",
        b"document1",
        2,
        999
    )

    assert result is False


def test_different_documents_have_separate_state():
    state = {}

    result1 = check_freshness(
        state,
        b"alice",
        b"document1",
        1,
        1000
    )

    result2 = check_freshness(
        state,
        b"alice",
        b"document2",
        1,
        1000
    )

    assert result1 is True
    assert result2 is True


def test_different_senders_have_separate_state():
    state = {}

    result1 = check_freshness(
        state,
        b"alice",
        b"document1",
        1,
        1000
    )

    result2 = check_freshness(
        state,
        b"bob",
        b"document1",
        1,
        1000
    )

    assert result1 is True
    assert result2 is True


def test_remove_freshness_state():
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        1,
        1000
    )

    result = remove_freshness_state(
        state,
        b"alice",
        b"document1"
    )

    assert result is True
    assert (b"alice", b"document1") not in state


def test_duplicate_sequence_is_rejected():
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        5,
        1000
    )

    result = check_freshness(
        state,
        b"alice",
        b"document1",
        5,
        2000
    )

    assert result is False


def test_state_can_be_saved_and_loaded(tmp_path):
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        5,
        1000
    )

    filename = tmp_path / "freshness.txt"

    save_freshness_state(
        filename,
        state
    )

    loaded_state = load_freshness_state(
        filename
    )

    assert loaded_state == state


def test_replay_is_rejected_after_loading_state(tmp_path):
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        5,
        1000
    )

    filename = tmp_path / "freshness.txt"

    save_freshness_state(
        filename,
        state
    )

    loaded_state = load_freshness_state(
        filename
    )

    result = check_freshness(
        loaded_state,
        b"alice",
        b"document1",
        5,
        1000
    )

    assert result is False


def test_newer_share_is_accepted_after_loading_state(tmp_path):
    state = {}

    check_freshness(
        state,
        b"alice",
        b"document1",
        5,
        1000
    )

    filename = tmp_path / "freshness.txt"

    save_freshness_state(
        filename,
        state
    )

    loaded_state = load_freshness_state(
        filename
    )

    result = check_freshness(
        loaded_state,
        b"alice",
        b"document1",
        6,
        1001
    )

    assert result is True
