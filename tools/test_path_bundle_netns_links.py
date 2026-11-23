"""Strict observations for the opt-in two-stage owned link."""
import json
import unittest

from . import path_bundle_netns_links as links


def row(kind, handle, **identity):
    return dict(kind=kind, handle=handle, bytes=0, packets=0, drops=0,
                overlimits=0, requeues=0, **identity)


class SplitLinkObservationTests(unittest.TestCase):
    def test_only_the_expected_shaper_and_downstream_identities_are_accepted(self):
        endpoint = [row("htb", "1:", root=True), row("pfifo", "10:", parent="1:10")]
        downstream = [row("netem", "10:", root=True)]
        self.assertEqual(links.parse_qdiscs(json.dumps(endpoint), False), endpoint)
        self.assertEqual(links.parse_qdiscs(json.dumps(downstream), True), downstream)
        for rows, mode in ((endpoint, True), (downstream, False), (endpoint * 2, False),
                           ([row("htb", "1:", root=True), row("netem", "10:", parent="1:10")], False),
                           ([row("netem", "10:", parent="1:10")], True)):
            with self.assertRaises(Exception):
                links.parse_qdiscs(json.dumps(rows), mode)

    def test_absent_or_invalid_drop_counters_cannot_qualify_the_split_link(self):
        for value in (-1, True, "0", None):
            observed = row("netem", "10:", root=True)
            observed["drops"] = value
            with self.assertRaises(Exception):
                links.parse_qdiscs(json.dumps([observed]), True)


if __name__ == "__main__":
    unittest.main()
