from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).parents[1]
SITE = ROOT / "site"


class SiteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: set[str] = set()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"])
        if tag in {"a", "link"} and values.get("href"):
            self.links.append(values["href"])


def test_site_assets_and_internal_links_exist() -> None:
    parser = SiteParser()
    parser.feed((SITE / "index.html").read_text())
    assert (SITE / "styles.css").is_file()
    for link in parser.links:
        if link.startswith("#"):
            assert link[1:] in parser.ids
        elif not link.startswith(("http://", "https://")):
            assert (SITE / link).is_file()


def test_site_documents_install_and_privacy_boundary() -> None:
    page = (SITE / "index.html").read_text()
    assert "/claude-reposec:nr-scan" in page
    assert "/plugin marketplace add nikolareljin/claude-plugins" in page
    assert "Source code and file paths are never included" in page
    assert "https://nikolareljin.github.io/claude-plugins/" in page
