"""
Tests for the per-manifest exemption (ignore) ledger used while scanning
Python dependency files.

The exemption rules declared in the security policy must only be used as the
starting point of each manifest scan. The ledger mutated during a scan
(auto-ignores injected by rules, expired exemptions removed) has to be private
to that manifest: it must never be aliased by another file and it must never be
written back into the policy configuration.
"""

import copy
import json
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from safety.scan.ecosystems.python.main import PythonFile
from safety_schemas.models import (
    ConfigModel,
    FileType,
    IgnoredItemDetail,
    IgnoredItems,
    IgnoreCodes,
    VulnerabilitySeverityLabels,
)

# The shipped test database ships two django advisories ("some id" and
# "some other id"), both matching the "<1.9" specifier.
VULN_A = "some id"
VULN_B = "some other id"

TEST_DB_DIR = Path(__file__).parents[3] / "test_db"


@pytest.fixture
def vulnerability_databases():
    insecure_db = json.loads((TEST_DB_DIR / "insecure.json").read_text())
    insecure_full_db = json.loads(
        (TEST_DB_DIR / "insecure_full.json").read_text()
    )

    def fake_get_from_cache(db_name, skip_time_verification=False):
        if db_name == "insecure.json":
            return insecure_db
        if db_name == "insecure_full.json":
            return insecure_full_db
        return None

    with patch(
        "safety.scan.ecosystems.python.main.get_from_cache",
        side_effect=fake_get_from_cache,
    ):
        yield


@pytest.fixture
def make_python_file(tmp_path):
    opened_files = []

    def _factory(requirements_text, name="requirements.txt"):
        req_path = tmp_path / name
        req_path.write_text(requirements_text, encoding="utf-8")
        handle = open(req_path, mode="r+", encoding="utf-8")
        python_file = PythonFile(
            file_type=FileType.REQUIREMENTS_TXT, file=handle
        )
        opened_files.append(handle)
        return python_file

    yield _factory

    for handle in opened_files:
        handle.close()


def policy_with_manual_ignore(vuln_id, *, expires=None):
    config = ConfigModel()
    config.depedendency_vulnerability.ignore_vulnerabilities = IgnoredItems(
        {
            vuln_id: IgnoredItemDetail(
                code=IgnoreCodes.manual,
                reason="declared in the security policy",
                expires=expires,
            )
        }
    )
    return config


def all_vulnerability_ids(python_file):
    ids = set()
    for dependency in python_file.dependency_results.dependencies:
        for specification in dependency.specifications:
            ids.update(
                vulnerability.vulnerability_id
                for vulnerability in specification.vulnerabilities
            )
    return ids


def active_vulnerability_ids(python_file):
    """Vulnerability IDs that are reported (not silently ignored)."""
    ids = set()
    for dependency in python_file.dependency_results.dependencies:
        for specification in dependency.specifications:
            ids.update(
                vulnerability.vulnerability_id
                for vulnerability in specification.vulnerabilities
                if not vulnerability.ignored
            )
    return ids


def ignored_vulnerability_ids(python_file):
    return set(python_file.dependency_results.ignored_vulns.keys())


def test_cross_file_exemptions_do_not_leak_between_manifests(
    vulnerability_databases, make_python_file
):
    """
    A rule-generated exemption produced while scanning one manifest must not
    be inherited (and silently silence a vulnerability) by a later manifest.

    The severity rule is enabled for the first manifest only. It generates an
    exemption for VULN_B inside that manifest's ledger. The rule is then turned
    off before scanning the second manifest, so any VULN_B exemption present in
    the second manifest can only have leaked from the first one through a
    shared ledger. With per-file ledgers the second manifest correctly reports
    VULN_B again.
    """
    config = policy_with_manual_ignore(
        VULN_A, expires=date.today() + timedelta(days=30)
    )
    # The shipped advisories carry no CVE, hence an UNKNOWN severity label.
    config.depedendency_vulnerability.ignore_cvss_severity = [
        VulnerabilitySeverityLabels.UNKNOWN
    ]

    first_file = make_python_file("django==1.8.1\n", name="first.txt")
    first_file.inspect(config)

    # The first manifest legitimately auto-ignored VULN_B through its rule.
    assert VULN_B in first_file.dependency_results.ignored_vulns
    assert VULN_B not in active_vulnerability_ids(first_file)

    # Turn the rule off before the second manifest is evaluated.
    config.depedendency_vulnerability.ignore_cvss_severity = []

    second_file = make_python_file("django==1.8.1\n", name="second.txt")
    second_file.inspect(config)

    first_ledger = first_file.dependency_results.ignored_vulns
    second_ledger = second_file.dependency_results.ignored_vulns
    policy_ledger = config.depedendency_vulnerability.ignore_vulnerabilities

    # The second manifest must not inherit the first manifest's rule-generated
    # exemption: VULN_B is reported again and is absent from its ledger.
    assert VULN_B in active_vulnerability_ids(second_file)
    assert VULN_B not in second_ledger

    # The policy-declared manual exemption still applies to both manifests.
    assert VULN_A in first_ledger
    assert VULN_A in second_ledger
    assert VULN_A not in active_vulnerability_ids(second_file)

    # Every manifest keeps its own ledger; none alias the policy or each other.
    assert first_ledger is not second_ledger
    assert first_ledger is not policy_ledger
    assert second_ledger is not policy_ledger


def test_each_manifest_holds_an_independent_exemption_ledger(
    vulnerability_databases, make_python_file
):
    """
    The per-file results and the policy must not share the same ledger object;
    mutating one manifest's ledger must not deform the others or the report.
    """
    config = policy_with_manual_ignore(
        VULN_A, expires=date.today() + timedelta(days=30)
    )

    first_file = make_python_file("django==1.8.1\n", name="first.txt")
    second_file = make_python_file("django==1.8.1\n", name="second.txt")

    first_file.inspect(config)
    second_file.inspect(config)

    policy_ledger = config.depedendency_vulnerability.ignore_vulnerabilities
    first_ledger = first_file.dependency_results.ignored_vulns
    second_ledger = second_file.dependency_results.ignored_vulns

    assert first_ledger is not policy_ledger
    assert second_ledger is not policy_ledger
    assert first_ledger is not second_ledger

    # Every copy has to be fully detached, including the nested detail objects
    # and their mutable specification sets.
    assert first_ledger[VULN_A] is not policy_ledger[VULN_A]
    assert second_ledger[VULN_A] is not policy_ledger[VULN_A]
    assert first_ledger[VULN_A] is not second_ledger[VULN_A]

    # A post-scan change to one manifest's ledger cannot reach the others.
    first_ledger[VULN_A].reason = "mutated after the scan"
    assert second_ledger[VULN_A].reason == "declared in the security policy"
    assert policy_ledger[VULN_A].reason == "declared in the security policy"


def test_scanning_does_not_mutate_the_policy_configuration(
    vulnerability_databases, make_python_file
):
    """
    Scanning must not write rule-generated exemptions back into the policy, and
    expired manual exemptions must keep their existing default behavior
    (removed from the per-file ledger and reported again) without being deleted
    from the policy itself.
    """
    config = policy_with_manual_ignore(
        VULN_A, expires=date.today() - timedelta(days=1)
    )
    policy_ledger = config.depedendency_vulnerability.ignore_vulnerabilities
    policy_before = copy.deepcopy(dict(policy_ledger))

    python_file = make_python_file("django==1.8.1\n")
    python_file.inspect(config)

    # The policy object is untouched by the scan...
    assert config.depedendency_vulnerability.ignore_vulnerabilities is policy_ledger
    assert set(policy_ledger.keys()) == {VULN_A}
    assert policy_ledger[VULN_A].reason == policy_before[VULN_A].reason
    assert policy_ledger[VULN_A].expires == policy_before[VULN_A].expires
    assert policy_ledger[VULN_A].code is IgnoreCodes.manual

    # ...while the expired exemption still stops applying to this manifest and
    # the vulnerability is reported again (no default-behavior regression).
    assert VULN_A not in ignored_vulnerability_ids(python_file)
    assert VULN_A in all_vulnerability_ids(python_file)


def test_rule_generated_ignores_are_not_injected_into_the_policy(
    vulnerability_databases, make_python_file
):
    """
    Exemptions generated at scan time (severity/unpinned/environment rules)
    live only in the manifest's private ledger, never in the policy config.
    """
    config = policy_with_manual_ignore(
        VULN_A, expires=date.today() + timedelta(days=30)
    )
    config.depedendency_vulnerability.ignore_cvss_severity = [
        VulnerabilitySeverityLabels.UNKNOWN
    ]
    policy_ledger = config.depedendency_vulnerability.ignore_vulnerabilities

    python_file = make_python_file("django==1.8.1\n")
    python_file.inspect(config)

    # The scan auto-ignored the second advisory via the severity rule...
    per_file_ledger = python_file.dependency_results.ignored_vulns
    assert VULN_B in per_file_ledger
    assert per_file_ledger[VULN_B].code is IgnoreCodes.cvss_severity

    # ...but the policy still contains only the manually declared exemption.
    assert set(policy_ledger.keys()) == {VULN_A}
    assert policy_ledger[VULN_A].code is IgnoreCodes.manual
