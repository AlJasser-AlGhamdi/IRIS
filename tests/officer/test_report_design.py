import html
import re
from collections import Counter
from pathlib import Path

from officer.cli import sim_session

FEATURED = Path(__file__).resolve().parents[2] / "runs" / "featured"


def _text(page: str) -> str:
    page = re.sub(r"<style>.*?</style>|<svg.*?</svg>", "", page, flags=re.S)
    return html.unescape(re.sub(r"<[^>]+>", " ", page))


def test_report_uses_the_site_design(tmp_path: Path) -> None:
    sim_session(3, "honest", "scripted", tmp_path / "run.jsonl")
    page = (tmp_path / "run.report.html").read_text(encoding="utf-8")
    assert "--cyan:#35D7FF" in page and 'class="panel-index"' in page and "@media print" in page
    legend = sum(int(n) for n in re.findall(r"</i>[^<]*<b>(\d+)</b>", page))
    assert legend == 204
    assert "{'rows'" not in page and "&#x27;rows&#x27;" not in page


def test_featured_reports_carry_the_same_numbers_in_both_languages() -> None:
    ar = _text((FEATURED / "demo-qwen3.report.html").read_text(encoding="utf-8"))
    en = _text((FEATURED / "demo-qwen3.report.en.html").read_text(encoding="utf-8"))
    assert not re.search(r"[؀-ۿ]", en)
    ar = ar.translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789"))
    assert Counter(re.findall(r"\d+", ar)) == Counter(re.findall(r"\d+", en))
