#!/usr/bin/env python3
"""Check example downloads in the actual mdBook artifact, not only its sources."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import unittest

ROOT = Path(__file__).resolve().parent.parent
BOOK = ROOT / 'docs/book'
EXAMPLES = ROOT / 'docs/examples'
PREFIX = 'https://hushspec.org/docs-examples/'


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.links.extend(value for key, value in attrs if key == 'href' and value)


class BookDownloads(unittest.TestCase):
    def test_every_example_download_resolves_to_a_published_file(self):
        self.assertTrue((BOOK / 'index.html').is_file(), 'Run mdbook build docs first')
        checked = 0
        for page in BOOK.rglob('*.html'):
            parser = Links()
            parser.feed(page.read_text())
            for href in parser.links:
                parsed = urlsplit(href)
                if href.startswith(PREFIX):
                    target = (EXAMPLES / unquote(parsed.path.removeprefix('/docs-examples/'))).resolve()
                    self.assertTrue(target.is_relative_to(EXAMPLES.resolve()), href)
                    self.assertTrue(target.is_file(), href)
                    checked += 1
                elif not parsed.scheme and '../examples/' in parsed.path:
                    target = (page.parent / unquote(parsed.path)).resolve()
                    self.assertTrue(target.is_relative_to(BOOK.resolve()), f'{page.relative_to(BOOK)}: {href} escapes the published book')
                    self.assertTrue(target.is_file(), href)
                    checked += 1
        self.assertGreaterEqual(checked, 30, 'Expected quickstart, SDK and evidence downloads')


if __name__ == '__main__':
    unittest.main()
