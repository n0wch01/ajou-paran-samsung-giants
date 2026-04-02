import pytest

from claw_defender.viz.cvss31 import (
    CVSS31Error,
    compute_cvss31,
    preset_vector,
)


def test_compute_cvss31_full_vector() -> None:
    r = compute_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N")
    assert r.base_score == pytest.approx(8.2)
    assert r.base_severity == "HIGH"
    assert r.vector_string.startswith("CVSS:3.1/")
    assert r.cvss_json["version"] == "3.1"


def test_compute_cvss31_prefix_optional() -> None:
    r = compute_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    assert r.base_score == pytest.approx(7.5)
    assert "AV:N" in r.vector_string


def test_preset_vectors_are_31() -> None:
    for sid in ("A1", "B1", "C1"):
        r = compute_cvss31(preset_vector(sid))
        assert r.cvss_json["version"] == "3.1"
        assert 0.0 <= r.base_score <= 10.0


def test_rejects_cvss2_or_malformed() -> None:
    with pytest.raises(CVSS31Error):
        compute_cvss31("not-a-vector")
    with pytest.raises(CVSS31Error):
        compute_cvss31("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:N")
