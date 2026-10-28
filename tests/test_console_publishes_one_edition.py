"""One scan must not print two OWASP editions, and no surface may derive an id by string.

A first-time reader ran the README's headline command on 2026-10-28 and got a category
table saying

    LLM07    Misinformation                          4     0     0
    LLM08    Hidden Context Exposure             not exercised this run

with a coverage footer eight lines below it saying

    Not exercised:
      - LLM07: System Prompt Leakage
      - LLM08: Vector and Embedding Weaknesses

so LLM07 was exercised and not exercised in the same output. Neither block was internally
wrong: the table resolved ids through the edition in force, the footer published the 2025
storage ids. The reader could not tell whether the application had been tested, which is
the one question the tool exists to answer.

Two independent places caused it and each is pinned below:

* ``statistics.get_coverage_gaps`` read ``cat.id`` / ``cat.name`` straight off
  ``OWASP_LLM_CATEGORIES``, whose values are the 2025 form by design, instead of going
  through ``get_owasp_category``.
* ``__main__._print_coverage_footer``'s ``cid()`` was
  ``marker.replace("owasp_llm", "LLM")``. Marker keys deliberately never move when an
  edition renumbers, so a string transform of a marker IS the 2025 numbering.

The SARIF was correct throughout and ``--validate`` passed, so every data-level gate stayed
green. That is why these tests read the RENDERED console text: the defect only ever existed
in the rendering.

The third test is the one that matters most, and it is deliberately written against the
PROPERTY rather than against today's names. The four tests that were supposed to guard this
footer all hardcoded published ids, and because ``cid()`` derived ids the same way the test
authors did, test and defect agreed with each other for the whole migration. Asserting
"equal to what the resolver says" cannot rot that way; asserting "equal to LLM09" can, and
did.
"""

from __future__ import annotations

import pytest

from llmsectest import envvars
from llmsectest.reporting.models import TestResult
from llmsectest.reporting.owasp_metadata import (
    OWASP_LLM_CATEGORIES,
    get_owasp_category,
    resolve_edition,
)
from llmsectest.reporting.statistics import get_coverage_gaps


def _result(marker: str, outcome: str = "passed") -> TestResult:
    return TestResult(
        nodeid=f"tests/test_{marker}.py::test_{marker}",
        location=(f"tests/test_{marker}.py", 1, f"test_{marker}"),
        outcome=outcome,
        duration=0.01,
        markers=[marker],
    )


def test_coverage_gaps_publishes_the_edition_in_force_not_the_storage_ids():
    """Every id and name in the gap report equals what the edition resolver publishes."""
    gaps = get_coverage_gaps([_result("owasp_llm01")])

    assert gaps["edition"] == resolve_edition()
    assert gaps["untested"], "a one-category run must leave gaps to check"

    for row in gaps["untested"] + gaps["tested"]:
        expected = get_owasp_category(row["marker"], gaps["edition"])
        assert row["id"] == expected.id, (
            f"{row['marker']} published id {row['id']!r}, the {gaps['edition']} edition "
            f"says {expected.id!r}"
        )
        assert row["name"] == expected.name, (
            f"{row['marker']} published name {row['name']!r}, the {gaps['edition']} "
            f"edition says {expected.name!r}"
        )


def test_the_gap_report_disagrees_with_the_raw_table_wherever_the_edition_renumbers():
    """The negative control: without it the test above passes on a broken implementation
    whenever the edition in force happens to change nothing.

    If this fails because the default edition stopped renumbering anything, that is not a
    defect and the test should be deleted rather than loosened.
    """
    gaps = get_coverage_gaps([_result("owasp_llm01")])
    rows = {row["marker"]: row for row in gaps["untested"] + gaps["tested"]}

    renumbered = [
        marker
        for marker, category in OWASP_LLM_CATEGORIES.items()
        if marker in rows and get_owasp_category(marker, gaps["edition"]).id != category.id
    ]
    assert renumbered, (
        f"the {gaps['edition']} edition renumbers nothing in this run's categories, so "
        "the assertion above cannot distinguish a resolved id from a raw one"
    )
    for marker in renumbered:
        assert rows[marker]["id"] != OWASP_LLM_CATEGORIES[marker].id


@pytest.mark.parametrize("target", ["app:http://127.0.0.1:9/chat", None])
def test_no_console_footer_line_publishes_an_id_from_a_marker_string(
    capsys, monkeypatch, target
):
    """Every LLMxx in the coverage footer is an id the resolver publishes.

    Both branches of the footer are covered, because the app-target branch and the
    model-target branch build their lists separately and only one of them was exercised by
    the tests that existed.
    """
    from llmsectest.__main__ import _print_coverage_footer

    for name in (envvars.REPO, envvars.MODEL_SCAN, envvars.VECTOR_STORE):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(envvars.APP_PROMPT, "You are a bot. The token is SECRET-1.")
    monkeypatch.setenv(envvars.APP_SECRET, "SECRET-1")

    _print_coverage_footer(target)
    out = capsys.readouterr().out

    edition = resolve_edition()

    # ‼‼ WHAT DOES NOT WORK, recorded because two drafts of this test were vacuous and
    # the second one PASSED with the defect deliberately reinstated.
    #
    # The 2026 edition is a PERMUTATION of the 2025 numbering. A footer built by string-
    # replacing markers prints the same ten strings LLM01..LLM10 as a correct one; only the
    # pairing differs. So neither "is this id published anywhere" nor "does this id appear
    # in the output" can tell the two apart, and a set-difference of stale ids against
    # published ids is empty by construction. The footer prints no category NAMES either,
    # so pairing an id with a name silently tests nothing here.
    #
    # WHAT DISCRIMINATES is each line's own FLAG HINT. The reason text beside a category is
    # looked up by marker, so it stays attached to its category across editions while the
    # id beside it does not. `--repo` belongs to owasp_llm03, which publishes as LLM04
    # under 2026 and as LLM03 under 2025 — a one-line check that fails loudly on the bug.
    flag_markers = {
        "--repo": "owasp_llm03",
        "--model-scan": "owasp_llm04",
        "--app-action": "owasp_llm06",
        "--app-canary": "owasp_llm08",
    }

    checked = 0
    for flag, marker in sorted(flag_markers.items()):
        right = get_owasp_category(marker, edition).id
        wrong = marker.replace("owasp_llm", "LLM")
        lines = [
            ln for ln in out.splitlines() if flag in ln and "not exercised" in ln
        ]
        if not lines:
            continue
        for line in lines:
            assert right in line, (
                f"the footer line offering {flag} should name {right} ({marker} under the "
                f"{edition} edition) and does not. {wrong} is that marker's 2025 id, so a "
                f"footer naming it is publishing the storage numbering.\n{line}"
            )
            if right != wrong:
                assert wrong not in line, (
                    f"the footer line offering {flag} names {wrong}, this marker's 2025 "
                    f"id, where the {edition} edition publishes {right}.\n{line}"
                )
            checked += 1

    assert checked, (
        "no 'not exercised' line carried a flag hint, so this run measured nothing. The "
        f"footer was:\n{out}"
    )
