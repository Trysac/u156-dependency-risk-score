"""Comprehensive tests for dependency_risk_score verifying all requirements and acceptance cases."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from dependency_risk_score import (
    DEFAULT_LICENSES,
    Package,
    RiskError,
    Vulnerability,
    Weights,
    load_facts,
    score_all,
    score_package,
)
from dependency_risk_score.__main__ import main


def test_acceptance_spec_case_1() -> None:
    """With as_of date(2026, 11, 6), package {'name': 'a', 'version': '1.0.0', 'last_release': '2023-01-01', 'maintainers': 1, 'license': 'GPL-3.0-only', 'deprecated': False, 'vulnerabilities': [{'id': 'GHSA-aaaa-bbbb-cccc', 'severity': 'high'}]} scores 75 with level 'high' and reasons ('stale_release', 'single_maintainer', 'strong_copyleft', 'vulnerability:GHSA-aaaa-bbbb-cccc:high')"""
    pkg = Package(
        name="a",
        version="1.0.0",
        last_release=date(2023, 1, 1),
        maintainers=1,
        license="GPL-3.0-only",
        deprecated=False,
        vulnerabilities=(Vulnerability(id="GHSA-aaaa-bbbb-cccc", severity="high"),),
    )
    report = score_package(pkg, as_of=date(2026, 11, 6))
    assert report.score == 75
    assert report.level == "high"
    assert report.reasons == (
        "stale_release",
        "single_maintainer",
        "strong_copyleft",
        "vulnerability:GHSA-aaaa-bbbb-cccc:high",
    )


def test_acceptance_spec_case_2() -> None:
    """A package released '2026-10-01' with 3 maintainers, license 'MIT' and no vulnerabilities scores 0 with level 'low' and reasons ()"""
    pkg = Package(
        name="clean-pkg",
        version="2.0.0",
        last_release=date(2026, 10, 1),
        maintainers=3,
        license="MIT",
        deprecated=False,
        vulnerabilities=(),
    )
    report = score_package(pkg, as_of=date(2026, 11, 6))
    assert report.score == 0
    assert report.level == "low"
    assert report.reasons == ()


def test_acceptance_spec_case_3() -> None:
    """A deprecated package released '2026-06-01' with 2 maintainers, license 'MIT' and vulnerabilities of severity 'critical', 'critical' and 'high' scores 85 with level 'critical': the vulnerability part is capped at 60 and deprecation adds 25"""
    pkg = Package(
        name="vuln-pkg",
        version="0.9.0",
        last_release=date(2026, 6, 1),
        maintainers=2,
        license="MIT",
        deprecated=True,
        vulnerabilities=(
            Vulnerability(id="VULN-1", severity="critical"),
            Vulnerability(id="VULN-2", severity="critical"),
            Vulnerability(id="VULN-3", severity="high"),
        ),
    )
    report = score_package(pkg, as_of=date(2026, 11, 6))
    # Vulnerabilities sum: 40 + 40 + 25 = 105 -> capped at 60
    # Deprecation: 25 -> total = 85
    assert report.score == 85
    assert report.level == "critical"
    assert report.reasons == (
        "deprecated",
        "vulnerability:VULN-1:critical",
        "vulnerability:VULN-2:critical",
        "vulnerability:VULN-3:high",
    )


def test_acceptance_spec_case_4() -> None:
    """Release age boundaries: 365 days old adds 0, 366 days adds 10 ('aging_release'), 730 days adds 10 and 731 days adds 20 ('stale_release'); 0 maintainers adds 10 with reason 'single_maintainer'"""
    ref_date = date(2026, 1, 1)

    # 365 days ago
    pkg_365 = Package(
        name="p365",
        version="1.0.0",
        last_release=date(2025, 1, 1),
        maintainers=2,
        license="MIT",
    )
    assert (ref_date - date(2025, 1, 1)).days == 365
    report_365 = score_package(pkg_365, as_of=ref_date)
    assert "aging_release" not in report_365.reasons
    assert "stale_release" not in report_365.reasons
    assert report_365.score == 0

    # 366 days ago
    pkg_366 = Package(
        name="p366",
        version="1.0.0",
        last_release=date(2024, 12, 31),
        maintainers=2,
        license="MIT",
    )
    assert (ref_date - date(2024, 12, 31)).days == 366
    report_366 = score_package(pkg_366, as_of=ref_date)
    assert report_366.reasons == ("aging_release",)
    assert report_366.score == 10

    # 730 days ago (2024 was leap year, 366+365=731, so 2024-01-02 is 730 days)
    pkg_730 = Package(
        name="p730",
        version="1.0.0",
        last_release=date(2024, 1, 2),
        maintainers=2,
        license="MIT",
    )
    assert (ref_date - date(2024, 1, 2)).days == 730
    report_730 = score_package(pkg_730, as_of=ref_date)
    assert report_730.reasons == ("aging_release",)
    assert report_730.score == 10

    # 731 days ago
    pkg_731 = Package(
        name="p731",
        version="1.0.0",
        last_release=date(2024, 1, 1),
        maintainers=2,
        license="MIT",
    )
    assert (ref_date - date(2024, 1, 1)).days == 731
    report_731 = score_package(pkg_731, as_of=ref_date)
    assert report_731.reasons == ("stale_release",)
    assert report_731.score == 20

    # 0 maintainers
    pkg_0_maint = Package(
        name="p0maint",
        version="1.0.0",
        last_release=ref_date,
        maintainers=0,
        license="MIT",
    )
    report_0_maint = score_package(pkg_0_maint, as_of=ref_date)
    assert report_0_maint.reasons == ("single_maintainer",)
    assert report_0_maint.score == 10


def test_acceptance_spec_case_5() -> None:
    """License 'LGPL-2.1-or-later' adds 10 ('weak_copyleft'), 'AGPL-3.0-only' adds 20 ('strong_copyleft'), and None, 'NOASSERTION', 'MIT OR GPL-3.0-only' or an unlisted id add 15 ('unknown_license')"""
    ref_date = date(2026, 11, 6)

    pkg_weak = Package(name="w", version="1", license="LGPL-2.1-or-later")
    rep_weak = score_package(pkg_weak, as_of=ref_date)
    assert rep_weak.reasons == ("weak_copyleft",)
    assert rep_weak.score == 10

    pkg_strong = Package(name="s", version="1", license="AGPL-3.0-only")
    rep_strong = score_package(pkg_strong, as_of=ref_date)
    assert rep_strong.reasons == ("strong_copyleft",)
    assert rep_strong.score == 20

    for unk in (None, "NOASSERTION", "MIT OR GPL-3.0-only", "UNLISTED-1.0"):
        pkg_unk = Package(name="u", version="1", license=unk)
        rep_unk = score_package(pkg_unk, as_of=ref_date)
        assert rep_unk.reasons == ("unknown_license",)
        assert rep_unk.score == 15


def test_acceptance_spec_case_6() -> None:
    """score_all returns reports sorted by score descending then name ascending, and Weights(critical=50) changes the critical vulnerability weight while Weights(high=-1) raises RiskError with code 'invalid_weights'"""
    ref_date = date(2026, 11, 6)
    p1 = Package(name="beta", version="1", license="LGPL-2.1-only")  # score 10
    p2 = Package(name="alpha", version="1", license="LGPL-2.1-only")  # score 10
    p3 = Package(name="gamma", version="1", license="GPL-3.0-only")  # score 20

    reports = score_all([p1, p2, p3], as_of=ref_date)
    assert [r.name for r in reports] == ["gamma", "alpha", "beta"]
    assert [r.score for r in reports] == [20, 10, 10]

    # Custom weights
    w_custom = Weights(critical=50)
    assert w_custom.critical == 50
    pkg_crit = Package(
        name="crit",
        version="1",
        license="MIT",
        vulnerabilities=(Vulnerability(id="V", severity="critical"),),
    )
    rep_custom = score_package(pkg_crit, as_of=ref_date, weights=w_custom)
    assert rep_custom.score == 50

    # Invalid weight
    with pytest.raises(RiskError) as exc_info:
        Weights(high=-1)
    assert exc_info.value.code == "invalid_weights"

    # Boolean weight must also be rejected
    with pytest.raises(RiskError) as exc_info_bool:
        Weights(high=True)  # type: ignore
    assert exc_info_bool.value.code == "invalid_weights"


def test_acceptance_spec_case_7() -> None:
    """A facts file of 5_242_881 bytes raises RiskError with code 'input_too_large', 10_001 packages raise 'input_too_large', a last_release '2026-13-01' raises 'invalid_date' and a missing name raises 'invalid_facts' naming packages[0]"""
    # 5_242_881 bytes
    large_text = " " * 5_242_881
    with pytest.raises(RiskError) as exc_size:
        load_facts(large_text)
    assert exc_size.value.code == "input_too_large"

    # 10_001 packages
    lots_of_pkgs = {"packages": [{"name": f"pkg-{i}", "version": "1.0.0"} for i in range(10_001)]}
    with pytest.raises(RiskError) as exc_pkgs:
        load_facts(json.dumps(lots_of_pkgs))
    assert exc_pkgs.value.code == "input_too_large"

    # invalid date '2026-13-01'
    bad_date = json.dumps(
        {"packages": [{"name": "pkg", "version": "1.0.0", "last_release": "2026-13-01"}]}
    )
    with pytest.raises(RiskError) as exc_date:
        load_facts(bad_date)
    assert exc_date.value.code == "invalid_date"
    assert "packages[0].last_release" in str(exc_date.value)

    # missing name naming packages[0]
    missing_name = json.dumps({"packages": [{"version": "1.0.0"}]})
    with pytest.raises(RiskError) as exc_name:
        load_facts(missing_name)
    assert exc_name.value.code == "invalid_facts"
    assert "packages[0]" in str(exc_name.value)


def test_acceptance_spec_case_8(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """main(['facts.json', '--as-of', '2026-11-06', '--fail-on', 'high']) returns 1 when any package is 'high' or 'critical' and 0 otherwise, '--format json' prints valid JSON, and a missing file returns 2"""
    facts_high = tmp_path / "high.json"
    facts_high.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "a",
                        "version": "1.0.0",
                        "last_release": "2023-01-01",
                        "maintainers": 1,
                        "license": "GPL-3.0-only",
                        "deprecated": False,
                        "vulnerabilities": [{"id": "GHSA-1", "severity": "high"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    facts_low = tmp_path / "low.json"
    facts_low.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "b",
                        "version": "1.0.0",
                        "last_release": "2026-10-01",
                        "maintainers": 3,
                        "license": "MIT",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    # Fail-on high with high risk package -> returns 1
    rc1 = main([str(facts_high), "--as-of", "2026-11-06", "--fail-on", "high"])
    assert rc1 == 1

    # Fail-on high with low risk package -> returns 0
    rc2 = main([str(facts_low), "--as-of", "2026-11-06", "--fail-on", "high"])
    assert rc2 == 0

    # Clear captured buffer before running format json check
    capsys.readouterr()

    # format json
    rc_json = main([str(facts_low), "--as-of", "2026-11-06", "--format", "json"])
    assert rc_json == 0
    captured = capsys.readouterr()
    parsed_out = json.loads(captured.out)
    assert isinstance(parsed_out, list)
    assert parsed_out[0]["name"] == "b"
    assert parsed_out[0]["level"] == "low"

    # format text line format: '<score> <level> <name>@<version> <reasons comma-joined>'
    rc_text = main([str(facts_high), "--as-of", "2026-11-06", "--format", "text"])
    assert rc_text == 0
    capsys.readouterr()

    rc_text_no_fail = main([str(facts_high), "--as-of", "2026-11-06"])
    assert rc_text_no_fail == 0
    captured_text = capsys.readouterr()
    assert (
        "75 high a@1.0.0 stale_release,single_maintainer,strong_copyleft,vulnerability:GHSA-1:high\n"
        in captured_text.out
    )

    # Missing file returns 2
    rc_missing = main([str(tmp_path / "nonexistent.json"), "--as-of", "2026-11-06"])
    assert rc_missing == 2


def test_facts_parsing_validation_edge_cases() -> None:
    """Validate facts edge cases, limits, and errors."""
    # Not a JSON
    with pytest.raises(RiskError) as exc_non_json:
        load_facts("not valid json{")
    assert exc_non_json.value.code == "invalid_facts"

    # Not a dict
    with pytest.raises(RiskError) as exc_non_dict:
        load_facts("[]")
    assert exc_non_dict.value.code == "invalid_facts"

    # Missing packages key
    with pytest.raises(RiskError) as exc_no_pkgs:
        load_facts("{}")
    assert exc_no_pkgs.value.code == "invalid_facts"

    # packages not list
    with pytest.raises(RiskError) as exc_pkg_not_list:
        load_facts(json.dumps({"packages": "invalid"}))
    assert exc_pkg_not_list.value.code == "invalid_facts"

    # package not dict
    with pytest.raises(RiskError) as exc_pkg_not_dict:
        load_facts(json.dumps({"packages": ["bad"]}))
    assert exc_pkg_not_dict.value.code == "invalid_facts"

    # empty or whitespace name
    with pytest.raises(RiskError) as exc_name_empty:
        load_facts(json.dumps({"packages": [{"name": "   ", "version": "1.0"}]}))
    assert exc_name_empty.value.code == "invalid_facts"

    # name not string
    with pytest.raises(RiskError) as exc_name_type:
        load_facts(json.dumps({"packages": [{"name": 123, "version": "1.0"}]}))
    assert exc_name_type.value.code == "invalid_facts"

    # missing version
    with pytest.raises(RiskError) as exc_ver_missing:
        load_facts(json.dumps({"packages": [{"name": "a"}]}))
    assert exc_ver_missing.value.code == "invalid_facts"

    # version not string or empty
    with pytest.raises(RiskError) as exc_ver_empty:
        load_facts(json.dumps({"packages": [{"name": "a", "version": ""}]}))
    assert exc_ver_empty.value.code == "invalid_facts"

    # last_release not string
    with pytest.raises(RiskError) as exc_lr_type:
        load_facts(json.dumps({"packages": [{"name": "a", "version": "1", "last_release": 123}]}))
    assert exc_lr_type.value.code == "invalid_facts"

    # last_release bad length or invalid format
    with pytest.raises(RiskError) as exc_lr_fmt:
        load_facts(
            json.dumps({"packages": [{"name": "a", "version": "1", "last_release": "2026/01/01"}]})
        )
    assert exc_lr_fmt.value.code == "invalid_date"

    with pytest.raises(RiskError) as exc_lr_short:
        load_facts(
            json.dumps({"packages": [{"name": "a", "version": "1", "last_release": "2026-01"}]})
        )
    assert exc_lr_short.value.code == "invalid_date"

    # maintainers invalid type or < 0
    with pytest.raises(RiskError) as exc_maint_bool:
        load_facts(json.dumps({"packages": [{"name": "a", "version": "1", "maintainers": True}]}))
    assert exc_maint_bool.value.code == "invalid_facts"

    with pytest.raises(RiskError) as exc_maint_neg:
        load_facts(json.dumps({"packages": [{"name": "a", "version": "1", "maintainers": -1}]}))
    assert exc_maint_neg.value.code == "invalid_facts"

    # license not string
    with pytest.raises(RiskError) as exc_lic_type:
        load_facts(json.dumps({"packages": [{"name": "a", "version": "1", "license": 123}]}))
    assert exc_lic_type.value.code == "invalid_facts"

    # deprecated not bool
    with pytest.raises(RiskError) as exc_dep_type:
        load_facts(json.dumps({"packages": [{"name": "a", "version": "1", "deprecated": "yes"}]}))
    assert exc_dep_type.value.code == "invalid_facts"

    # vulnerabilities not list
    with pytest.raises(RiskError) as exc_vuln_type:
        load_facts(
            json.dumps({"packages": [{"name": "a", "version": "1", "vulnerabilities": "vuln"}]})
        )
    assert exc_vuln_type.value.code == "invalid_facts"

    # vulnerabilities > 1000
    too_many_vulns = [{"id": f"GHSA-{i}", "severity": "low"} for i in range(1_001)]
    with pytest.raises(RiskError) as exc_vuln_len:
        load_facts(
            json.dumps(
                {"packages": [{"name": "a", "version": "1", "vulnerabilities": too_many_vulns}]}
            )
        )
    assert exc_vuln_len.value.code == "input_too_large"

    # vulnerability item not dict
    with pytest.raises(RiskError) as exc_v_dict:
        load_facts(
            json.dumps({"packages": [{"name": "a", "version": "1", "vulnerabilities": ["bad"]}]})
        )
    assert exc_v_dict.value.code == "invalid_facts"

    # vulnerability id missing or empty
    with pytest.raises(RiskError) as exc_v_id:
        load_facts(
            json.dumps(
                {"packages": [{"name": "a", "version": "1", "vulnerabilities": [{"id": " "}]}]}
            )
        )
    assert exc_v_id.value.code == "invalid_facts"

    # vulnerability severity invalid
    with pytest.raises(RiskError) as exc_v_sev:
        load_facts(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "a",
                            "version": "1",
                            "vulnerabilities": [{"id": "1", "severity": "negligible"}],
                        }
                    ]
                }
            )
        )
    assert exc_v_sev.value.code == "invalid_facts"


def test_vulnerability_severities_and_caps() -> None:
    """Exercise medium and low severity vulnerabilities and score capping at 100."""
    pkg = Package(
        name="p",
        version="1",
        last_release=date(2020, 1, 1),  # stale -> +20
        maintainers=0,  # single_maintainer -> +10
        deprecated=True,  # deprecated -> +25
        license="GPL-3.0-only",  # strong_copyleft -> +20
        vulnerabilities=(
            Vulnerability(id="V1", severity="medium"),  # +10
            Vulnerability(id="V2", severity="low"),  # +3
            Vulnerability(id="V3", severity="critical"),  # +40
            Vulnerability(id="V4", severity="high"),  # +25 -> sum 78, capped at 60
        ),
    )
    # Non-vuln score: 20 + 10 + 25 + 20 = 75
    # Vuln score capped: 60
    # Total: 75 + 60 = 135 -> capped at 100
    rep = score_package(pkg, as_of=date(2026, 11, 6))
    assert rep.score == 100
    assert rep.level == "critical"
    assert rep.reasons == (
        "stale_release",
        "single_maintainer",
        "deprecated",
        "strong_copyleft",
        "vulnerability:V1:medium",
        "vulnerability:V2:low",
        "vulnerability:V3:critical",
        "vulnerability:V4:high",
    )


def test_weights_bounds() -> None:
    """Weights must reject out-of-range (>100 or <0) values."""
    with pytest.raises(RiskError) as exc1:
        Weights(aging=101)
    assert exc1.value.code == "invalid_weights"

    with pytest.raises(RiskError) as exc2:
        Weights(vuln_cap=-5)
    assert exc2.value.code == "invalid_weights"


def test_cli_parsing_and_errors(tmp_path: Path) -> None:
    """Test CLI argument validation, invalid dates, and invalid JSON files."""
    # Bad CLI args
    assert main([]) == 2

    # Invalid --as-of date format
    dummy = tmp_path / "empty.json"
    dummy.write_text(json.dumps({"packages": []}))
    assert main([str(dummy), "--as-of", "not-a-date"]) == 2
    assert main([str(dummy), "--as-of", "2026-13-40"]) == 2

    # Facts file with invalid facts
    bad_facts = tmp_path / "bad.json"
    bad_facts.write_text("not valid json")
    assert main([str(bad_facts), "--as-of", "2026-11-06"]) == 2


def test_default_licenses_bundled_table() -> None:
    """Verify DEFAULT_LICENSES contains all required SPDX identifiers."""
    expected_permissive = {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "Zlib",
        "Unlicense",
        "PSF-2.0",
    }
    expected_weak = {
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
        "EPL-2.0",
    }
    expected_strong = {
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
    }
    for lic in expected_permissive:
        assert DEFAULT_LICENSES[lic] == "permissive"
    for lic in expected_weak:
        assert DEFAULT_LICENSES[lic] == "weak_copyleft"
    for lic in expected_strong:
        assert DEFAULT_LICENSES[lic] == "strong_copyleft"
