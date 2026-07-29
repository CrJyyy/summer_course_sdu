import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class SummarizeResultsTest(unittest.TestCase):
    def test_uses_final_evaluated_attempts_and_writes_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            results_dir = Path(temp_dir)
            report = results_dir / "prompt-injection.report.jsonl"
            rows = [
                {
                    "entry_type": "start_run setup",
                    "_config.version": "0.16.0.pre1",
                    "plugins.target_name": "example/model",
                },
                {
                    "entry_type": "attempt",
                    "uuid": "pass-id",
                    "status": 1,
                    "probe_classname": "example.Probe",
                    "prompt": {"turns": [{"content": {"text": "pass prompt"}}]},
                    "outputs": [{"text": "pass output"}],
                    "detector_results": {},
                },
                {
                    "entry_type": "attempt",
                    "uuid": "pass-id",
                    "status": 2,
                    "probe_classname": "example.Probe",
                    "prompt": {"turns": [{"content": {"text": "pass prompt"}}]},
                    "outputs": [{"text": "pass output"}],
                    "detector_results": {"example.Detector": [0.0]},
                },
                {
                    "entry_type": "attempt",
                    "uuid": "fail-id",
                    "status": 2,
                    "probe_classname": "example.Probe",
                    "prompt": {"turns": [{"content": {"text": "fail prompt"}}]},
                    "outputs": [{"text": "fail output"}],
                    "detector_results": {"example.Detector": [1.0]},
                },
                {
                    "entry_type": "eval",
                    "probe": "example.Probe",
                    "detector": "example.Detector",
                    "passed": 1,
                    "fails": 1,
                    "nones": 0,
                    "total_evaluated": 2,
                },
                {"entry_type": "completion", "end_time": "2026-07-25T20:00:00"},
            ]
            report.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )

            script = Path(__file__).parents[1] / "summarize_results.py"
            completed = subprocess.run(
                [sys.executable, str(script), str(results_dir)],
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads(
                (results_dir / "summary.json").read_text(encoding="utf-8")
            )
            result = summary["results"][0]
            self.assertEqual(result["total"], 2)
            self.assertEqual(result["fails"], 1)
            self.assertEqual(result["attack_success_rate"], 50.0)
            self.assertEqual(result["examples"]["fail"][0]["uuid"], "fail-id")
            self.assertEqual(result["examples"]["pass"][0]["uuid"], "pass-id")

    def test_preserves_unicode_line_separator_inside_json_string(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            results_dir = Path(temp_dir)
            report = results_dir / "jailbreak.report.jsonl"
            rows = [
                {
                    "entry_type": "start_run setup",
                    "_config.version": "0.16.0.pre1",
                    "plugins.target_name": "example/model",
                },
                {
                    "entry_type": "attempt",
                    "uuid": "unicode-id",
                    "status": 2,
                    "probe_classname": "example.Probe",
                    "prompt": {"turns": [{"content": {"text": "prompt"}}]},
                    "outputs": [{"text": "beforeafter"}],
                    "detector_results": {"example.Detector": [1.0]},
                },
                {
                    "entry_type": "eval",
                    "probe": "example.Probe",
                    "detector": "example.Detector",
                    "passed": 0,
                    "fails": 1,
                    "nones": 0,
                    "total_evaluated": 1,
                },
                {"entry_type": "completion", "end_time": "2026-07-25T20:00:00"},
            ]
            with report.open("w", encoding="utf-8") as report_file:
                for row in rows:
                    report_file.write(json.dumps(row, ensure_ascii=False) + "\n")

            script = Path(__file__).parents[1] / "summarize_results.py"
            completed = subprocess.run(
                [sys.executable, str(script), str(results_dir)],
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads(
                (results_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                summary["results"][0]["examples"]["fail"][0]["output"],
                "beforeafter",
            )


if __name__ == "__main__":
    unittest.main()
