from datasovereign.crypto import protect, unprotect


def test_dpapi_round_trip_and_randomized_ciphertext():
    first = protect(b"private document")
    second = protect(b"private document")

    assert first != b"private document"
    assert first != second
    assert unprotect(first) == b"private document"
    assert unprotect(second) == b"private document"
