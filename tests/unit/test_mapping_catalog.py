"""OSCAL catalog tests: schema validity, exact counts, IDs, bilingual parts (Phase 4).

Covers the Phase-4 acceptance gate: catalogs OSCAL-valid, control counts exact
(108 main + the encoded subcontrols), every ID well-formed and unique, tiers +
bilingual parts present for the scanner-observable controls.
"""

from __future__ import annotations

import json

import pytest

from p2c.mapping.catalog import (
    ECC_CATALOG,
    NCNICC_CATALOG,
    is_valid_native_id,
    load_default_index,
    native_to_oscal,
    oscal_to_native,
)


def test_catalogs_are_oscal_valid() -> None:
    # trestle re-parses + validates the generated JSON against the OSCAL model.
    trestle_catalog = pytest.importorskip("trestle.oscal.catalog")
    for path in (ECC_CATALOG, NCNICC_CATALOG):
        catalog = trestle_catalog.Catalog.oscal_read(path)
        assert catalog.metadata.oscal_version == "1.1.2"


def test_ecc_has_exactly_108_main_controls() -> None:
    index = load_default_index()
    assert len(index.main_controls()) == 108


def test_ecc_has_exactly_92_subcontrols() -> None:
    # The full official subcontrol count, now encoded from the authoritative NCA PDF
    # (was 65 when only the toolkit taxonomy's key subcontrols were available).
    assert len(load_default_index().subcontrols()) == 92


@pytest.mark.skip(reason="control statement text is withheld from this public copy (see NOTICE)")
def test_ddos_subcontrol_2_5_3_9_present() -> None:
    # 2-5-3-9 (DDoS) uses hyphen id-form in the PDF while its siblings use dots — a
    # regression guard that the extractor handles both forms.
    entry = load_default_index().get("2-5-3-9")
    assert entry is not None and "DDoS" in entry.statement_en


def test_all_28_subdomains_present() -> None:
    assert len(load_default_index().subdomains()) == 28


def test_every_control_id_is_unique_and_well_formed() -> None:
    index = load_default_index()
    ids = [e.native_id for e in index.entries.values()]
    assert len(ids) == len(set(ids))  # unique
    assert all(is_valid_native_id(cid) for cid in ids)


@pytest.mark.skip(reason="control statement text is withheld from this public copy (see NOTICE)")
def test_every_control_has_tier_and_english_statement() -> None:
    for entry in load_default_index().entries.values():
        assert entry.tier in (1, 2, 3), entry.native_id
        assert entry.statement_en, entry.native_id


@pytest.mark.skipif(
    "private" not in str(ECC_CATALOG),
    reason="Arabic parts are withheld from the stripped public catalog",
)
def test_tier1_controls_are_bilingual() -> None:
    # The scanner-observable controls (the ones that flow through mapping/reporting)
    # must carry an Arabic statement, not just English.
    index = load_default_index()
    tier1_subcontrols = [e for e in index.by_tier(1) if e.is_subcontrol]
    assert len(tier1_subcontrols) == 11  # the 11 Tier-1 subcontrols (2026-10-20 recode)
    for entry in tier1_subcontrols:
        assert entry.statement_ar, f"{entry.native_id} missing Arabic statement"


def test_subcontrols_nested_under_valid_parents() -> None:
    index = load_default_index()
    for sub in index.subcontrols():
        parent_id = sub.native_id.rsplit("-", 1)[0]
        assert index.is_valid(parent_id), f"{sub.native_id} has no parent {parent_id}"


def test_ncnicc_exclusive_controls_present() -> None:
    index = load_default_index()
    for cid in ("2-7-1-2", "2-12-1-2", "2-7-1-3"):
        entry = index.get(cid)
        assert entry is not None and entry.framework == "ncnicc"


def test_native_oscal_id_roundtrip() -> None:
    assert native_to_oscal("2-5-3-1", "ecc") == "ecc-2-5-3-1"
    assert oscal_to_native("ecc-2-5-3-1") == "2-5-3-1"
    assert oscal_to_native("ncnicc-2-7-1-2") == "2-7-1-2"


@pytest.mark.skip(reason="control statement text is withheld from this public copy (see NOTICE)")
def test_no_latex_residue_in_control_prose() -> None:
    # The tex parser must fully de-LaTeX: no `$...$` math, no stray `\macro`/`\ ` escapes
    # leaking into English statement/assessment/remediation prose (e.g. `$\geq$`).
    index = load_default_index()
    for entry in index.entries.values():
        for text in (entry.statement_en, entry.assessment_en, entry.remediation_en):
            assert "$" not in text, f"{entry.native_id}: LaTeX math residue in {text!r}"
            assert "\\" not in text, f"{entry.native_id}: LaTeX escape residue in {text!r}"
    # The HSTS control's remediation specifically carried `$\geq$` -> must be the glyph.
    assert "≥ 15 768 000" in index.require("2-15-3-3").remediation_en


def test_no_header_leak_in_control_text() -> None:
    # Guards the extractor: no clause may contain a domain-title watermark or a stray
    # subdomain header (the 4 leaks found in review: 1-6-4, 2-2-3-1, 2-15-4, 3-1-4).
    leaks = ("Cybersecurity Governance", "Cybersecurity Defense", "Third-Party and Cloud Computing")
    index = load_default_index()
    for entry in index.entries.values():
        for bad in leaks:
            assert bad not in entry.statement_en, f"{entry.native_id}: leaked header {bad!r}"
    # "Cybersecurity Resilience" is a legitimate substring of subdomain 3-1's controls,
    # so assert the specific reviewed leak is gone rather than banning the phrase.
    assert not index.require("2-15-4").statement_en.endswith("Cybersecurity Resilience")


@pytest.mark.skipif(
    "private" not in str(ECC_CATALOG),
    reason="Arabic parts are withheld from the stripped public catalog",
)
def test_authoritative_arabic_recovered_after_rtl_dereversal() -> None:
    # The RTL 2-digit-subdomain de-reversal recovers binding Arabic for subdomains 10/12/13/15.
    index = load_default_index()
    for cid in ("2-10-2", "2-15-1", "2-13-2", "1-10-2", "2-12-1"):
        entry = index.require(cid)
        assert entry.statement_ar and entry.statement_ar.startswith("يجب"), cid


def test_catalog_metadata_records_subcontrol_coverage() -> None:
    # Honest coverage: 108 main exact; encoded subcontrols recorded against the
    # official 92 (the non-key subcontrols await the official Arabic source).
    doc = json.loads(ECC_CATALOG.read_text(encoding="utf-8"))
    props = {p["name"]: p["value"] for p in doc["catalog"]["metadata"]["props"]}
    assert props["main-controls"] == "108"
    assert props["subcontrols-official"] == "92"
    # Gap closed: encoded == official == 92 (authoritative NCA PDF source).
    assert props["subcontrols-encoded"] == "92"
    assert int(props["subcontrols-encoded"]) == len(load_default_index().subcontrols())
