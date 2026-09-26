import io
import unittest

from tools import authshadowreport


class ShadowReportTests(unittest.TestCase):
    def test_summarizes_only_shadow_records(self):
        lines = io.StringIO(
            "not json\n"
            '{"msg":"other"}\n'
            '{"msg":"authentication shadow comparison","completed":true,'
            '"matched":true,"compared_methods":2,"duration_ms":10,'
            '"shadow_error":"","differences":[],"detail_differences":[],'
            '"spf":{"compared":true},"dkim":{"compared":true},"dmarc":{"compared":false}}\n'
            '{"msg":"authentication shadow comparison","completed":true,'
            '"matched":false,"compared_methods":1,"duration_ms":30,'
            '"shadow_error":"","differences":["dkim"],'
            '"detail_differences":["dkim"],"spf":{"compared":false},'
            '"dkim":{"compared":true,"internal_reasons":["DKIM key revoked"]},'
            '"dmarc":{"compared":false}}\n'
            '{"msg":"authentication shadow comparison","completed":false,'
            '"matched":false,"compared_methods":0,"duration_ms":20,'
            '"shadow_error":"timeout","spf":{},"dkim":{},"dmarc":{}}\n'
        )
        got = authshadowreport.summarize(lines)
        self.assertEqual(got["records"], 3)
        self.assertEqual(got["completed"], 2)
        self.assertEqual(got["with_trusted_reference"], 2)
        self.assertEqual(got["without_trusted_reference"], 1)
        self.assertEqual(got["semantic_matches"], 1)
        self.assertEqual(got["semantic_differences"], 1)
        self.assertEqual(got["shadow_errors"], {"timeout": 1})
        self.assertEqual(got["method_comparisons"], {"dkim": 2, "spf": 1})
        self.assertEqual(got["method_differences"], {"dkim": 1})
        self.assertEqual(got["method_detail_differences"], {"dkim": 1})
        self.assertEqual(got["internal_reasons"], {"DKIM key revoked": 1})
        self.assertEqual(got["latency_ms"], {"median": 20, "p95": 30, "max": 30})
        self.assertEqual(got["ignored_non_json_lines"], 1)


if __name__ == "__main__":
    unittest.main()
