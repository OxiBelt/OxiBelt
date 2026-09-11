#!/usr/bin/env python3
"""Contract tests for the local performance campaign wrapper.

The fixture deliberately replaces Docker, the performance harness, and the
aggregate binary.  It therefore checks campaign orchestration and fail-closed
handling without building an image or running a benchmark.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("run-local-performance-campaign.sh")
GROUPS = (
    "reverse-proxy",
    "static-files",
    "oxibelt-features",
    "remote-signer",
    "oxibelt-soak-stress",
)
TARGETS = ("x86-64-v2", "x86-64-v3")


def write_executable(path: pathlib.Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


class LocalPerformanceCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="oxibelt-local-campaign-")
        self.root = pathlib.Path(self.temporary.name)
        self.source = self.root / "source"
        scripts = self.source / "tests" / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(SCRIPT, scripts / SCRIPT.name)
        (scripts / SCRIPT.name).chmod(0o755)

        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.inputs = self.root / "images.json"
        self.aggregate = self.bin / "aggregate"
        self.docker = self.bin / "docker"
        self.timeout = self.bin / "timeout"
        self.runner_record = self.root / "runner-record.jsonl"
        self.aggregate_record = self.root / "aggregate-record.jsonl"
        self.timeout_record = self.root / "timeout-record.jsonl"

        write_executable(
            scripts / "run-proxy-performance.sh",
            r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys
import time

args = sys.argv[1:]
profile = args[args.index("--profile") + 1]
group = args[args.index("--serving-type") + 1]
target = os.environ.get("OXIBELT_AMD64_TARGET_CPU", "")
stdin_bytes = sys.stdin.buffer.read()
def image_identity(reference):
    return {
        "reference": reference,
        "image_id": reference,
        "repo_digests": [],
        "created": "2026-09-09T00:00:00Z",
        "os": "linux",
        "architecture": "amd64",
        "version_label": None,
        "revision_label": None,
    }
images = {
    "perf_probe": image_identity(os.environ.get("OXIBELT_PERF_PROBE_IMAGE", "")),
    "oxibelt": image_identity(os.environ.get("OXIBELT_DOCKER_IMAGE", "")),
    "nginx": image_identity(os.environ.get("OXIBELT_NGINX_IMAGE", "")),
    "caddy": image_identity(os.environ.get("OXIBELT_CADDY_IMAGE", "")),
    "openresty": image_identity(os.environ.get("OXIBELT_OPENRESTY_IMAGE", "")),
}
record_path = pathlib.Path(os.environ["FAKE_RUNNER_RECORD"])
with record_path.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"profile": profile, "group": group,
                             "target": target, "stdin_bytes": len(stdin_bytes),
                             "keep_test_artifacts": os.environ.get("KEEP_TEST_ARTIFACTS", ""),
                             "images": {
                                 "oxibelt": os.environ.get("OXIBELT_DOCKER_IMAGE", ""),
                                 "keysigner": os.environ.get("OXIBELT_KEYSIGNER_DOCKER_IMAGE", ""),
                                 "nginx": os.environ.get("OXIBELT_NGINX_IMAGE", ""),
                                 "caddy": os.environ.get("OXIBELT_CADDY_IMAGE", ""),
                                 "openresty": os.environ.get("OXIBELT_OPENRESTY_IMAGE", ""),
                                 "perf_probe": os.environ.get("OXIBELT_PERF_PROBE_IMAGE", ""),
                                 "external": os.environ.get("OXIBELT_EXTERNAL_BENCHMARK_IMAGE", ""),
                             }}) + "\n")

artifact = pathlib.Path(os.environ["OXIBELT_TEST_ARTIFACT_DIR"])
artifact.mkdir(parents=True, exist_ok=True)
(artifact / "proxy-tls").mkdir(exist_ok=True)
(artifact / "proxy-tls" / "privkey.pem").write_text("private fixture key\n", encoding="utf-8")
(artifact / "proxy-tls" / "quic-host-key.b64").write_text("private fixture key\n", encoding="utf-8")
(artifact / "configs" / "oxibelt-fixture" / "cert").mkdir(parents=True, exist_ok=True)
(artifact / "configs" / "oxibelt-fixture" / "cert" / "privkey.pem").write_text("private fixture key\n", encoding="utf-8")
(artifact / "configs" / "oxibelt-fixture" / "cert" / "keysigner-token.b64").write_text("private fixture key\n", encoding="utf-8")
profile_sleep_variable = f"FAKE_{profile.upper()}_RUNNER_SLEEP_SECONDS"
time.sleep(
    float(
        os.environ.get(
            profile_sleep_variable, os.environ.get("FAKE_RUNNER_SLEEP_SECONDS", "0")
        )
    )
)
result_profile = os.environ.get("FAKE_RESULT_PROFILE", profile)
(artifact / "results.json").write_text(json.dumps([{
    "label": "fixture",
    "comparator": "oxibelt",
    "scenario": "fixture",
    "protocol": "h1",
    "amd64_target_cpu": target,
    "profile": result_profile,
    "rps": 1.0,
    "p99_ms": 1.0,
    "errors": 0,
    "benchmark_identity": {
        "source_sha": os.environ.get("FAKE_SOURCE_REVISION", ""),
        "source_dirty": False,
        "profile": profile,
        "serving_type": group,
        "images": images,
    },
}]), encoding="utf-8")
sys.exit(int(os.environ.get("FAKE_RUNNER_EXIT", "0")))
''',
        )

        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.email", "fixture@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.name", "Fixture"],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.source), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "commit", "-qm", "fixture"], check=True
        )
        self.revision = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.tree = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()

        write_executable(self.docker, self._docker_fixture())
        write_executable(self.aggregate, self._aggregate_fixture())
        write_executable(self.timeout, self._timeout_fixture())
        self.inputs.write_text(json.dumps(self._input_manifest(), indent=2), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _docker_fixture(self) -> str:
        return f'''#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import time

if sys.argv[1:3] != ["image", "inspect"] or len(sys.argv) != 4:
    raise SystemExit("fixture docker only supports image inspect")
time.sleep(float(os.environ.get("FAKE_DOCKER_SLEEP_SECONDS", "0")))
reference = sys.argv[3]
config_digest = "sha256:" + hashlib.sha256(reference.encode()).hexdigest()
manifest_digest = "sha256:" + hashlib.sha256(
    ("manifest:" + reference).encode()
).hexdigest()
store_mode = os.environ.get("FAKE_DOCKER_IMAGE_STORE", "classic")
if store_mode.startswith("containerd"):
    image_id = manifest_digest
else:
    image_id = config_digest
labels = {{}}
if "oxibelt" in reference or "keysigner" in reference:
    labels["org.opencontainers.image.revision"] = (
        "wrong-source" if os.environ.get("FAKE_DOCKER_SOURCE_MISMATCH") else "{self.revision}"
    )
else:
    comparator = next((name for name in ("nginx", "caddy", "openresty") if name in reference), "")
    target = "x86-64-v3" if "v3" in reference else "x86-64-v2"
    if os.environ.get("FAKE_DOCKER_ISA_MISMATCH"):
        target = "x86-64-v2" if target == "x86-64-v3" else "x86-64-v3"
    labels["org.oxibelt.performance.comparator"] = comparator
    labels["org.oxibelt.performance.amd64_target_cpu"] = target
print(json.dumps([{{
    "Id": image_id,
    "RepoDigests": [reference + "@sha256:" + hashlib.sha256(reference.encode()).hexdigest()],
    "Created": "2026-09-09T00:00:00Z",
    "Os": "linux",
    "Architecture": "amd64",
    "Config": {{"Labels": labels}},
    **({{
        "Descriptor": {{
            "mediaType": (
                "application/vnd.oci.image.manifest.v1+json"
                if store_mode != "containerd-bad-type"
                else "application/vnd.docker.distribution.manifest.v2+json"
            ),
            "digest": (
                image_id
                if store_mode != "containerd-bad-digest"
                else "sha256:" + "e" * 64
            ),
        }}
        if store_mode != "containerd-missing-descriptor" and store_mode.startswith("containerd")
        else {{}}
    }}),
}}]))
'''

    @staticmethod
    def _aggregate_fixture() -> str:
        return r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys
import time

args = sys.argv[1:]
def value(flag):
    return args[args.index(flag) + 1]

output = pathlib.Path(value("--output-dir"))
output.mkdir(parents=True, exist_ok=True)
stdin_bytes = sys.stdin.buffer.read()
record = {
    "args": args,
    "profile": value("--profile"),
    "primary_target_cpu": value("--primary-target-cpu"),
    "expected_target_cpus": value("--expected-target-cpus"),
    "stdin_bytes": len(stdin_bytes),
}
record_path = os.environ.get("FAKE_AGGREGATE_RECORD")
if record_path:
    with pathlib.Path(record_path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
time.sleep(float(os.environ.get("FAKE_AGGREGATE_SLEEP_SECONDS", "0")))

mode = os.environ.get("FAKE_AGGREGATE_MODE", "pass")
report = output / "performance-comparison.json"
if mode == "command-fail":
    print("fixture aggregate failed", file=sys.stderr)
    raise SystemExit(42)
if mode == "no-report":
    raise SystemExit(0)
if mode == "malformed-report":
    report.write_text("not-json\n", encoding="utf-8")
    raise SystemExit(0)

payload = {
    "schema_version": 33,
    "profile": "benchmark",
    "primary_target_cpu": value("--primary-target-cpu"),
    "expected_target_cpus": value("--expected-target-cpus").split(","),
    "quorum": {"status": "pass", "violations": []},
    "regression_gates": {
        "status": "pass",
        "violations": [],
        "accepted_regression": {"status": "inactive"},
    },
}
if mode == "failed-json":
    payload["quorum"]["status"] = "fail"
    payload["regression_gates"]["status"] = "fail"
elif mode == "wrong-profile":
    payload["profile"] = "smoke"
elif mode == "wrong-isa":
    payload["primary_target_cpu"] = "x86-64-v4"
elif mode == "wrong-source":
    payload["source"] = {"revision": "wrong-source"}
elif mode == "missing-violations":
    payload["quorum"].pop("violations")
    payload["regression_gates"].pop("violations")
report.write_text(json.dumps(payload), encoding="utf-8")
(output / "performance-comparison.md").write_text("fixture\n", encoding="utf-8")
'''

    @staticmethod
    def _timeout_fixture() -> str:
        return r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
index = 0
while index < len(args) and args[index].startswith("-"):
    index += 1
if index + 1 >= len(args):
    raise SystemExit("fixture timeout could not locate duration and command")
duration = args[index]
command = args[index + 1]
record_path = os.environ.get("FAKE_TIMEOUT_RECORD")
if record_path:
    with pathlib.Path(record_path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "args": args,
            "duration": duration,
            "command": command,
        }) + "\n")
force = os.environ.get("FAKE_TIMEOUT_FORCE", "")
command_name = pathlib.Path(command).name
if force == "all" or (force == "input" and command_name == "docker") or (
    force == "runner" and command_name == "run-proxy-performance.sh"
) or (
    force == "aggregate" and command_name == "aggregate"
):
    args[index] = os.environ.get("FAKE_TIMEOUT_SECONDS", "0.1s")
os.execv("/usr/bin/timeout", ["timeout", *args])
'''

    def _input_manifest(self) -> dict[str, object]:
        targets: dict[str, dict[str, str]] = {}
        contracts = self.root / "contracts"
        contracts.mkdir()
        for target in TARGETS:
            suffix = "v2" if target.endswith("v2") else "v3"
            oxibelt_reference = f"oxibelt:{suffix}"
            keysigner_reference = f"keysigner:{suffix}"
            targets[target] = {
                "oxibelt_image": oxibelt_reference,
                "keysigner_image": keysigner_reference,
                "oxibelt_contract": f"contracts/{target}-oxibelt.json",
                "keysigner_contract": f"contracts/{target}-keysigner.json",
                "nginx_image": f"nginx:{target}",
                "caddy_image": f"caddy:{target}",
                "openresty_image": f"openresty:{target}",
            }
            for role, reference, suffix_name in (
                ("standalone", oxibelt_reference, "oxibelt"),
                ("keysigner", keysigner_reference, "keysigner"),
            ):
                image_id = "sha256:" + hashlib.sha256(reference.encode()).hexdigest()
                digest = "sha256:" + hashlib.sha256(
                    f"{target}:{role}".encode()
                ).hexdigest()
                (contracts / f"{target}-{suffix_name}.json").write_text(
                    json.dumps(
                        {
                            "artifact_arch": "amd64",
                            "binaries": [],
                            "build_kind": "fixture",
                            "build_metadata": "fixture",
                            "build_parameters": {},
                            "cargo_builds": [],
                            "config_digest": image_id,
                            "created": "2026-09-09T00:00:00Z",
                            "descriptor_digest": digest,
                            "docker_architecture": "amd64",
                            "docker_target": target,
                            "image_digest": image_id,
                            "image_tar": f"{suffix_name}.tar",
                            "image_tar_sha256": digest,
                            "layers": [],
                            "normalized_config_sha256": digest,
                            "platform": "linux/amd64",
                            "ref_name": reference,
                            "schema": 3,
                            "revision": self.revision,
                            "source_dirty": "clean",
                            "role": role,
                            "source": "fixture",
                            "source_inputs": {},
                            "source_inputs_sha256": digest,
                            "source_ref": "fixture",
                            "source_tree": self.tree,
                            "target_cpu": target,
                            "rust_target": "x86_64-unknown-linux-gnu",
                            "version": "fixture",
                        }
                    ),
                    encoding="utf-8",
                )
        return {
            "schema_version": 1,
            "common": {
                "perf_probe_image": "perf-probe:fixture",
                "external_benchmark_image": "external-benchmark:fixture",
            },
            "targets": targets,
        }

    def _rewrite_contracts_for_containerd(self, mismatch: str | None = None) -> None:
        for contract_path in sorted((self.root / "contracts").glob("*.json")):
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            reference = contract["ref_name"]
            manifest_digest = "sha256:" + hashlib.sha256(
                ("manifest:" + reference).encode()
            ).hexdigest()
            contract["image_digest"] = manifest_digest
            contract["descriptor_digest"] = manifest_digest
            if mismatch == "image_digest" and contract_path.name.endswith(
                "x86-64-v2-oxibelt.json"
            ):
                contract["image_digest"] = "sha256:" + "f" * 64
            if mismatch == "descriptor_digest" and contract_path.name.endswith(
                "x86-64-v2-oxibelt.json"
            ):
                contract["descriptor_digest"] = "sha256:" + "e" * 64
            contract_path.write_text(json.dumps(contract), encoding="utf-8")

    def _inflate_contract_source_inputs(self) -> pathlib.Path:
        contract_path = self.root / "contracts" / "x86-64-v2-oxibelt.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["source_inputs"] = {
            "fixture-source-manifest": "a" * 70_000,
            "fixture-source-lock": "b" * 70_000,
        }
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        return contract_path

    def _resolved_image_identity(self, reference: str, target: str | None = None) -> dict[str, object]:
        image_id = "sha256:" + hashlib.sha256(reference.encode()).hexdigest()
        labels: dict[str, str] = {}
        if "oxibelt" in reference or "keysigner" in reference:
            labels["org.opencontainers.image.revision"] = self.revision
        else:
            comparator = next(
                (name for name in ("nginx", "caddy", "openresty") if name in reference),
                "",
            )
            if comparator:
                labels["org.oxibelt.performance.comparator"] = comparator
                labels["org.oxibelt.performance.amd64_target_cpu"] = target or (
                    "x86-64-v3" if "v3" in reference else "x86-64-v2"
                )
        identity: dict[str, object] = {
            "reference": reference,
            "image_id": image_id,
            "repo_digests": [f"{reference}@{image_id}"],
            "created": "2026-09-09T00:00:00Z",
            "os": "linux",
            "architecture": "amd64",
            "labels": labels,
        }
        return identity

    def _runner_image_identity(self, reference: str) -> dict[str, object]:
        image_id = "sha256:" + hashlib.sha256(reference.encode()).hexdigest()
        return {
            "reference": image_id,
            "image_id": image_id,
            "repo_digests": [],
            "created": "2026-09-09T00:00:00Z",
            "os": "linux",
            "architecture": "amd64",
            "version_label": None,
            "revision_label": None,
        }

    def _resolved_inputs(self, campaign: pathlib.Path) -> dict[str, object]:
        raw = json.loads(self.inputs.read_text(encoding="utf-8"))
        common = {
            key: self._resolved_image_identity(raw["common"][key])
            for key in ("perf_probe_image", "external_benchmark_image")
        }
        targets: dict[str, dict[str, object]] = {}
        for target in TARGETS:
            target_raw = raw["targets"][target]
            target_resolved: dict[str, object] = {}
            for key in (
                "oxibelt_image",
                "keysigner_image",
                "nginx_image",
                "caddy_image",
                "openresty_image",
            ):
                target_resolved[key] = self._resolved_image_identity(
                    target_raw[key], target
                )
            for key in ("oxibelt_image", "keysigner_image"):
                contract_name = key.removesuffix("_image") + "_contract"
                contract_path = self.inputs.parent / target_raw[contract_name]
                contract = json.loads(contract_path.read_text(encoding="utf-8"))
                target_resolved[key]["artifact_contract"] = {
                    "path": str(contract_path),
                    "sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
                    "document": contract,
                }
            targets[target] = target_resolved
        resolved = {
            "schema_version": 1,
            "source": {"revision": self.revision, "tree": self.tree},
            "common": common,
            "targets": targets,
        }
        (campaign / "resolved-inputs.json").write_text(
            json.dumps(resolved, sort_keys=True, indent=2), encoding="utf-8"
        )
        return resolved

    def _tooling_identity(self) -> dict[str, object]:
        wrapper = self.source / "tests" / "scripts" / SCRIPT.name
        runner = self.source / "tests" / "scripts" / "run-proxy-performance.sh"

        def record(path: pathlib.Path) -> dict[str, str]:
            return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

        return {
            "wrapper": record(wrapper),
            "runner": record(runner),
            "aggregate": record(self.aggregate),
        }

    def invoke(
        self,
        phase: str,
        campaign: pathlib.Path,
        *extra: str,
        env: dict[str, str] | None = None,
        caller_umask: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command_env = os.environ.copy()
        command_env.update(
            {
                "OXIBELT_DOCKER_COMMAND": str(self.docker),
                "FAKE_RUNNER_RECORD": str(self.runner_record),
                "FAKE_AGGREGATE_RECORD": str(self.aggregate_record),
                "FAKE_TIMEOUT_RECORD": str(self.timeout_record),
                "FAKE_SOURCE_REVISION": self.revision,
                "XDG_RUNTIME_DIR": str(self.runtime),
                "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            }
        )
        if env:
            command_env.update(env)
        command = [
            str(self.source / "tests" / "scripts" / SCRIPT.name),
            "--phase",
            phase,
            "--inputs",
            str(self.inputs),
            "--source-root",
            str(self.source),
            "--campaign-dir",
            str(campaign),
            "--aggregate-bin",
            str(self.aggregate),
            *extra,
        ]
        return subprocess.run(
            command,
            cwd=self.root,
            env=command_env,
            text=True,
            capture_output=True,
            check=False,
            preexec_fn=(lambda: os.umask(caller_umask)) if caller_umask is not None else None,
        )

    def replace_fixed_campaign_timeout(self, variable: str, seconds: int) -> None:
        """Shorten one fixed deadline in the isolated committed fixture checkout."""
        wrapper = self.source / "tests" / "scripts" / SCRIPT.name
        prefix = f"readonly {variable}="
        lines = wrapper.read_text(encoding="utf-8").splitlines()
        matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
        self.assertEqual(len(matches), 1, prefix)
        lines[matches[0]] = f"{prefix}{seconds}"
        wrapper.write_text("\n".join(lines) + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.source), "add", str(wrapper)], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "commit", "--amend", "-qm", "fixture"],
            check=True,
        )
        self.revision = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.tree = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        write_executable(self.docker, self._docker_fixture())
        for contract_path in sorted((self.root / "contracts").glob("*.json")):
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            contract["revision"] = self.revision
            contract["source_tree"] = self.tree
            contract_path.write_text(json.dumps(contract), encoding="utf-8")

    def seed_full_benchmark(
        self,
        *,
        campaign: pathlib.Path | None = None,
        missing: pathlib.Path | None = None,
    ) -> pathlib.Path:
        campaign = campaign or (self.root / "campaign")
        campaign.mkdir(mode=0o700)
        planned: list[dict[str, object]] = []
        for target in TARGETS:
            for group in GROUPS:
                for iteration in range(1, 6):
                    relative = (
                        f"benchmark-input/oxibelt-docker-performance-benchmark-{group}-"
                        f"shard-1/{target}/run-{iteration}"
                    )
                    artifact = campaign / relative
                    artifact.mkdir(parents=True, exist_ok=True, mode=0o700)
                    if missing is None or pathlib.Path(relative) != missing:
                        (artifact / "results.json").write_text(
                            json.dumps(
                                [
                                    {
                                        "amd64_target_cpu": target,
                                        "benchmark_identity": {
                                            "source_sha": self.revision,
                                            "source_dirty": False,
                                            "profile": "benchmark",
                                            "serving_type": group,
                                            "images": {
                                                "perf_probe": self._runner_image_identity(
                                                    "perf-probe:fixture"
                                                ),
                                                "oxibelt": self._runner_image_identity(
                                                    f"oxibelt:{'v2' if target.endswith('v2') else 'v3'}"
                                                ),
                                                "nginx": self._runner_image_identity(
                                                    f"nginx:{target}"
                                                ),
                                                "caddy": self._runner_image_identity(
                                                    f"caddy:{target}"
                                                ),
                                                "openresty": self._runner_image_identity(
                                                    f"openresty:{target}"
                                                ),
                                            },
                                        },
                                    }
                                ]
                            ),
                            encoding="utf-8",
                        )
                    planned.append(
                        {
                            "target_cpu": target,
                            "group": group,
                            "iteration": iteration,
                            "artifact_dir": relative,
                        }
                    )
        manifest = {
            "schema_version": 1,
            "campaign_id": "campaign",
            "status": "collected",
            "source": {"revision": self.revision, "tree": self.tree},
            "inputs": self._resolved_inputs(campaign),
            "tooling": self._tooling_identity(),
            "planned": {"smoke": [], "benchmark": planned},
            "attempts": [
                {
                    "profile": "benchmark",
                    "target_cpu": entry["target_cpu"],
                    "group": entry["group"],
                    "iteration": entry["iteration"],
                    "artifact_dir": entry["artifact_dir"],
                    "exit_code": 0,
                    "status": "pass",
                }
                for entry in planned
            ],
            "aggregates": [],
        }
        (campaign / "campaign-manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        return campaign

    @staticmethod
    def passing_report(primary_target: str) -> dict[str, object]:
        return {
            "schema_version": 33,
            "profile": "benchmark",
            "primary_target_cpu": primary_target,
            "quorum": {"status": "pass", "violations": []},
            "regression_gates": {
                "status": "pass",
                "violations": [],
                "accepted_regression": {"status": "inactive"},
            },
        }

    def test_missing_and_malformed_reports_fail_closed(self) -> None:
        for mode in ("no-report", "malformed-report"):
            with self.subTest(mode=mode):
                campaign = self.seed_full_benchmark(
                    campaign=self.root / f"campaign-{mode}"
                )
                result = self.invoke(
                    "aggregate", campaign, env={"FAKE_AGGREGATE_MODE": mode}
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("aggregate gate failed", result.stderr)

    def test_exit_zero_failed_report_is_rejected_for_full_campaign(self) -> None:
        campaign = self.seed_full_benchmark()
        result = self.invoke(
            "aggregate", campaign, env={"FAKE_AGGREGATE_MODE": "failed-json"}
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("aggregate gate failed", result.stderr)

    def test_complete_dual_isa_campaign_is_a_passing_positive_control(self) -> None:
        campaign = self.seed_full_benchmark()
        result = self.invoke("aggregate", campaign)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = json.loads((campaign / "campaign-manifest.json").read_text())
        self.assertEqual(manifest["status"], "passed")
        self.assertEqual(
            [aggregate["status"] for aggregate in manifest["aggregates"]],
            ["pass", "pass"],
        )
        self.assertTrue(
            all(
                (campaign / aggregate["report_dir"] / "performance-comparison.json").is_file()
                for aggregate in manifest["aggregates"]
            )
        )

    def test_missing_report_violations_cannot_qualify_full_campaign(self) -> None:
        campaign = self.seed_full_benchmark()
        result = self.invoke(
            "aggregate", campaign, env={"FAKE_AGGREGATE_MODE": "missing-violations"}
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("aggregate gate failed", result.stderr)

    def test_mutable_image_refs_are_replaced_with_inspected_ids(self) -> None:
        campaign = self.root / "immutable-images"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        records = [
            json.loads(line)
            for line in self.runner_record.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(records), 1)
        images = records[0]["images"]
        self.assertEqual(set(images), {"oxibelt", "keysigner", "nginx", "caddy", "openresty", "perf_probe", "external"})
        self.assertTrue(all(value.startswith("sha256:") for value in images.values()))
        self.assertNotIn("oxibelt:v2", images.values())
        self.assertNotIn("nginx:x86-64-v2", images.values())

    def test_input_image_timeout_is_reported_distinctly(self) -> None:
        campaign = self.root / "input-timeout"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            env={
                "FAKE_TIMEOUT_FORCE": "input",
                "FAKE_DOCKER_SLEEP_SECONDS": "5",
            },
        )
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertIn("inspection timed out", result.stderr)
        self.assertFalse((campaign / "campaign-manifest.json").exists())
        self.assertFalse(self.runner_record.exists())
        timeout_record = json.loads(
            self.timeout_record.read_text(encoding="utf-8").strip()
        )
        self.assertEqual(timeout_record["duration"], "60s")
        self.assertEqual(pathlib.Path(timeout_record["command"]).name, "docker")

    def test_classic_config_id_image_store_remains_supported(self) -> None:
        campaign = self.root / "classic-image-store"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        resolved = json.loads(
            (campaign / "resolved-inputs.json").read_text(encoding="utf-8")
        )
        identity = resolved["targets"]["x86-64-v2"]["oxibelt_image"]
        contract = identity["artifact_contract"]["document"]
        self.assertEqual(identity["image_id"], contract["config_digest"])

    def test_oversized_valid_contract_is_resolved_and_retained(self) -> None:
        contract_path = self._inflate_contract_source_inputs()
        self.assertGreater(contract_path.stat().st_size, 128 * 1024)
        campaign = self.root / "oversized-contract"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        resolved = json.loads(
            (campaign / "resolved-inputs.json").read_text(encoding="utf-8")
        )
        document = resolved["targets"]["x86-64-v2"]["oxibelt_image"][
            "artifact_contract"
        ]["document"]
        self.assertEqual(
            document["source_inputs"]["fixture-source-manifest"], "a" * 70_000
        )
        self.assertEqual(
            document["source_inputs"]["fixture-source-lock"], "b" * 70_000
        )
        self.assertEqual(
            resolved["targets"]["x86-64-v2"]["oxibelt_image"]["artifact_contract"][
                "sha256"
            ],
            hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        )

    def test_containerd_manifest_identity_store_is_supported(self) -> None:
        self._rewrite_contracts_for_containerd()
        campaign = self.root / "containerd-image-store"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            env={"FAKE_DOCKER_IMAGE_STORE": "containerd"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        resolved = json.loads(
            (campaign / "resolved-inputs.json").read_text(encoding="utf-8")
        )
        identity = resolved["targets"]["x86-64-v2"]["oxibelt_image"]
        contract = identity["artifact_contract"]["document"]
        self.assertEqual(identity["image_id"], contract["image_digest"])
        self.assertEqual(identity["image_id"], contract["descriptor_digest"])
        self.assertNotEqual(identity["image_id"], contract["config_digest"])
        self.assertEqual(
            identity["descriptor"]["mediaType"],
            "application/vnd.oci.image.manifest.v1+json",
        )
        self.assertEqual(identity["descriptor"]["digest"], identity["image_id"])

    def test_containerd_descriptor_shape_is_required(self) -> None:
        for mode in (
            "containerd-missing-descriptor",
            "containerd-bad-digest",
            "containerd-bad-type",
        ):
            with self.subTest(mode=mode):
                self._rewrite_contracts_for_containerd()
                result = self.invoke(
                    "smoke",
                    self.root / mode,
                    "--target-cpu",
                    "x86-64-v2",
                    "--group",
                    "reverse-proxy",
                    env={"FAKE_DOCKER_IMAGE_STORE": mode},
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertRegex(result.stderr.lower(), r"descriptor|contract")
                self.assertFalse(self.runner_record.exists())

    def test_containerd_contract_image_and_descriptor_digests_must_bind(self) -> None:
        for mismatch in ("image_digest", "descriptor_digest"):
            with self.subTest(mismatch=mismatch):
                self._rewrite_contracts_for_containerd(mismatch=mismatch)
                result = self.invoke(
                    "smoke",
                    self.root / f"containerd-contract-{mismatch}",
                    "--target-cpu",
                    "x86-64-v2",
                    "--group",
                    "reverse-proxy",
                    env={"FAKE_DOCKER_IMAGE_STORE": "containerd"},
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("contract", result.stderr.lower())
                self.assertFalse(self.runner_record.exists())

    def test_inherited_threshold_override_is_rejected(self) -> None:
        result = self.invoke(
            "smoke",
            self.root / "inherited-override",
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            env={"OXIBELT_PERF_H1_KEEPALIVE_MIN_NGINX_RATIO": "0.01"},
        )
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("reject inherited", result.stderr)
        self.assertFalse(self.runner_record.exists())

    def test_inherited_threshold_override_is_rejected_during_aggregate(self) -> None:
        campaign = self.seed_full_benchmark()
        result = self.invoke(
            "aggregate",
            campaign,
            env={"OXIBELT_PERF_H1_KEEPALIVE_MIN_NGINX_RATIO": "0.01"},
        )
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("reject inherited", result.stderr)
        self.assertFalse(self.aggregate_record.exists())

    def test_symlinked_runtime_lock_directory_is_rejected(self) -> None:
        runtime = self.root / "symlink-runtime"
        runtime.mkdir(mode=0o700)
        lock_target = self.root / "lock-target"
        lock_target.mkdir(mode=0o700)
        lock_dir = runtime / f"oxibelt-local-performance-{os.getuid()}"
        lock_dir.symlink_to(lock_target, target_is_directory=True)

        result = self.invoke(
            "smoke",
            self.root / "symlink-lock",
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            env={"XDG_RUNTIME_DIR": str(runtime)},
        )
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertIn("must not be a symlink", result.stderr)
        self.assertFalse(self.runner_record.exists())

    def test_campaign_and_artifact_directories_are_private_under_umask_022(self) -> None:
        campaign = self.root / "private-artifacts"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            caller_umask=0o022,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = json.loads((campaign / "campaign-manifest.json").read_text())
        artifact = campaign / manifest["planned"]["smoke"][0]["artifact_dir"]
        self.assertEqual(campaign.stat().st_mode & 0o777, 0o700)
        self.assertEqual(artifact.stat().st_mode & 0o777, 0o700)

    def test_single_primary_baseline_is_rejected_for_the_other_isa(self) -> None:
        campaign = self.seed_full_benchmark()
        baseline = self.root / "v2-baseline.json"
        baseline.write_text(
            json.dumps(self.passing_report("x86-64-v2")), encoding="utf-8"
        )
        result = self.invoke(
            "aggregate", campaign, "--baseline-report", str(baseline)
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("x86-64-v3", result.stderr)

    def test_recorded_tooling_hash_mismatch_is_rejected_before_aggregate(self) -> None:
        campaign = self.seed_full_benchmark()
        manifest_path = campaign / "campaign-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["tooling"]["runner"]["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        result = self.invoke("aggregate", campaign)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tooling identity", result.stderr)
        self.assertFalse(self.aggregate_record.exists())

    def test_wrong_source_and_isa_image_identity_are_rejected(self) -> None:
        for variable, message in (
            ("FAKE_DOCKER_SOURCE_MISMATCH", "does not identify source revision"),
            ("FAKE_DOCKER_ISA_MISMATCH", "lacks the expected comparator"),
        ):
            with self.subTest(variable=variable):
                result = self.invoke(
                    "smoke",
                    self.root / variable.lower(),
                    "--target-cpu",
                    "x86-64-v2",
                    "--group",
                    "reverse-proxy",
                    env={variable: "1"},
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)

    def test_wrong_profile_report_is_rejected(self) -> None:
        campaign = self.seed_full_benchmark()
        result = self.invoke(
            "aggregate", campaign, env={"FAKE_AGGREGATE_MODE": "wrong-profile"}
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("aggregate gate failed", result.stderr)

    def test_missing_intended_sample_is_rejected_before_aggregate(self) -> None:
        missing = pathlib.Path(
            "benchmark-input/oxibelt-docker-performance-benchmark-reverse-proxy-"
            "shard-1/x86-64-v2/run-3"
        )
        campaign = self.seed_full_benchmark(missing=missing)
        result = self.invoke("aggregate", campaign)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("missing", result.stderr)
        self.assertIn("intended", result.stderr)
        self.assertFalse(self.aggregate_record.exists())

    def test_actual_result_image_id_mismatch_is_rejected_before_aggregate(self) -> None:
        campaign = self.seed_full_benchmark()
        manifest = json.loads(
            (campaign / "campaign-manifest.json").read_text(encoding="utf-8")
        )
        artifact = campaign / manifest["planned"]["benchmark"][0]["artifact_dir"]
        result_path = artifact / "results.json"
        results = json.loads(result_path.read_text(encoding="utf-8"))
        results[0]["benchmark_identity"]["images"]["oxibelt"]["image_id"] = (
            "sha256:" + "f" * 64
        )
        result_path.write_text(json.dumps(results), encoding="utf-8")

        result = self.invoke("aggregate", campaign)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("benchmark identity", result.stderr)
        self.assertFalse(self.aggregate_record.exists())

    def test_failed_baseline_is_rejected_before_aggregate(self) -> None:
        campaign = self.seed_full_benchmark()
        baseline = self.root / "failed-baseline.json"
        baseline.write_text(
            json.dumps(
                {
                    "schema_version": 33,
                    "quorum": {"status": "fail"},
                    "regression_gates": {
                        "status": "pass",
                        "accepted_regression": {"status": "inactive"},
                    },
                }
            ),
            encoding="utf-8",
        )
        result = self.invoke(
            "aggregate", campaign, "--baseline-report", str(baseline)
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not a passing", result.stderr)
        self.assertFalse(self.aggregate_record.exists())

    def test_baseline_without_empty_violations_is_rejected_before_aggregate(self) -> None:
        campaign = self.seed_full_benchmark()
        baseline = self.root / "incomplete-baseline.json"
        payload = self.passing_report("x86-64-v2")
        payload["quorum"].pop("violations")
        payload["regression_gates"].pop("violations")
        baseline.write_text(json.dumps(payload), encoding="utf-8")

        result = self.invoke(
            "aggregate", campaign, "--baseline-report", str(baseline)
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not a passing", result.stderr)
        self.assertFalse(self.aggregate_record.exists())

    def test_partial_group_selection_stays_diagnostic_only(self) -> None:
        campaign = self.root / "partial"
        collected = self.invoke(
            "benchmark",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
        )
        self.assertEqual(collected.returncode, 0, collected.stdout + collected.stderr)
        aggregated = self.invoke(
            "aggregate", campaign, env={"FAKE_AGGREGATE_MODE": "failed-json"}
        )
        self.assertEqual(aggregated.returncode, 0, aggregated.stdout + aggregated.stderr)
        manifest = json.loads((campaign / "campaign-manifest.json").read_text())
        self.assertEqual(manifest["status"], "diagnostic")
        self.assertEqual(len(manifest["aggregates"]), 1)
        self.assertEqual(manifest["aggregates"][0]["status"], "diagnostic")

    def test_skewed_or_duplicate_full_matrix_stays_diagnostic(self) -> None:
        for variant in ("skewed", "duplicate"):
            with self.subTest(variant=variant):
                campaign = self.seed_full_benchmark(
                    campaign=self.root / f"matrix-{variant}"
                )
                manifest_path = campaign / "campaign-manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if variant == "skewed":
                    manifest["planned"]["benchmark"].pop()
                else:
                    manifest["planned"]["benchmark"].append(
                        dict(manifest["planned"]["benchmark"][0])
                    )
                manifest_path.write_text(
                    json.dumps(manifest, indent=2), encoding="utf-8"
                )

                result = self.invoke("aggregate", campaign)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                self.assertEqual(manifest["status"], "diagnostic")
                self.assertTrue(
                    all(
                        aggregate["status"] == "diagnostic"
                        for aggregate in manifest["aggregates"]
                    )
                )

    def test_runner_failure_is_retained_and_every_child_gets_eof(self) -> None:
        campaign = self.root / "runner-failure"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            env={"FAKE_RUNNER_EXIT": "23"},
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        records = [
            json.loads(line)
            for line in self.runner_record.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["stdin_bytes"], 0)
        attempts = json.loads(
            (campaign / "campaign-manifest.json").read_text(encoding="utf-8")
        )["attempts"]
        self.assertEqual(attempts[0]["exit_code"], 23)
        self.assertEqual(attempts[0]["status"], "fail")

    def test_smoke_timeout_is_recorded_and_stops_the_phase(self) -> None:
        campaign = self.root / "smoke-timeout"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            env={
                "FAKE_TIMEOUT_FORCE": "runner",
                "FAKE_RUNNER_SLEEP_SECONDS": "5",
            },
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            len(self.runner_record.read_text(encoding="utf-8").splitlines()), 1
        )

        manifest = json.loads(
            (campaign / "campaign-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest["planned"]["smoke"]), len(GROUPS))
        self.assertEqual(len(manifest["attempts"]), 1)
        self.assertEqual(
            manifest["policy"]["timeout_seconds"],
            {
                "attempt": {"smoke": 1500, "benchmark": 3600},
                "aggregate": 900,
                "input_inspect": 60,
                "campaign": {"smoke": 7200, "benchmark": 72000, "all": 75600},
                "kill_after": 120,
            },
        )
        attempt = manifest["attempts"][0]
        self.assertEqual(attempt["runner_exit_code"], 124)
        self.assertEqual(attempt["status"], "timeout")
        self.assertTrue(attempt["timed_out"])
        self.assertEqual(attempt["timeout_scope"], "attempt")
        self.assertEqual(attempt["timeout_limit_seconds"], 1500)
        self.assertEqual(attempt["timeout_seconds"], 1500)
        receipt = campaign / attempt["restricted_receipt"]
        receipt_payload = json.loads(receipt.read_text())
        self.assertEqual(receipt_payload["status"], "removed")
        self.assertEqual(len(receipt_payload["removed"]), 4)

        all_timeout_records = [
            json.loads(line)
            for line in self.timeout_record.read_text(encoding="utf-8").splitlines()
        ]
        timeout_records = [
            record
            for record in all_timeout_records
            if pathlib.Path(record["command"]).name == "run-proxy-performance.sh"
        ]
        self.assertEqual(len(timeout_records), 1)
        self.assertEqual(timeout_records[0]["duration"], "1500s")
        self.assertEqual(
            pathlib.Path(timeout_records[0]["command"]).name,
            "run-proxy-performance.sh",
        )
        self.assertIn("--signal=TERM", timeout_records[0]["args"])
        self.assertIn("--kill-after=120s", timeout_records[0]["args"])

    def test_successful_smoke_attempt_uses_the_fixed_deadline(self) -> None:
        campaign = self.root / "smoke-deadline"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        timeout_record = next(
            record
            for record in (
                json.loads(line)
                for line in self.timeout_record.read_text(encoding="utf-8").splitlines()
            )
            if pathlib.Path(record["command"]).name == "run-proxy-performance.sh"
        )
        self.assertEqual(timeout_record["duration"], "1500s")
        attempt = json.loads(
            (campaign / "campaign-manifest.json").read_text(encoding="utf-8")
        )["attempts"][0]
        self.assertFalse(attempt["timed_out"])
        self.assertIsNone(attempt["timeout_scope"])
        self.assertEqual(attempt["status"], "pass")

    def test_all_stops_after_smoke_failure_without_benchmark_launch(self) -> None:
        campaign = self.root / "all-smoke-failure"
        result = self.invoke(
            "all",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            env={"FAKE_RUNNER_EXIT": "23"},
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        records = [
            json.loads(line)
            for line in self.runner_record.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([record["profile"] for record in records], ["smoke"])

    def test_all_campaign_deadline_stops_collection_before_aggregate(self) -> None:
        self.replace_fixed_campaign_timeout("all_campaign_timeout_seconds", 5)
        campaign = self.root / "all-campaign-timeout"
        result = self.invoke(
            "all",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            env={"FAKE_BENCHMARK_RUNNER_SLEEP_SECONDS": "10"},
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = json.loads(
            (campaign / "campaign-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["status"], "failed")
        self.assertEqual(
            [entry["profile"] for entry in manifest["attempts"]],
            ["smoke", "benchmark"],
        )
        benchmark = manifest["attempts"][1]
        self.assertEqual(benchmark["status"], "timeout")
        self.assertTrue(benchmark["timed_out"])
        self.assertEqual(benchmark["timeout_scope"], "campaign")
        self.assertLessEqual(benchmark["timeout_seconds"], 5)
        self.assertEqual(manifest["aggregates"], [])
        self.assertFalse(self.aggregate_record.exists())

    def test_generated_private_keys_are_removed_and_keep_artifacts_is_forced_off(
        self,
    ) -> None:
        campaign = self.root / "key-cleanup"
        result = self.invoke(
            "smoke",
            campaign,
            "--target-cpu",
            "x86-64-v2",
            "--group",
            "reverse-proxy",
            env={"KEEP_TEST_ARTIFACTS": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(self.runner_record.read_text(encoding="utf-8").strip())
        self.assertEqual(record["keep_test_artifacts"], "0")
        manifest = json.loads((campaign / "campaign-manifest.json").read_text())
        artifact = campaign / manifest["planned"]["smoke"][0]["artifact_dir"]
        for relative in (
            "proxy-tls/privkey.pem",
            "proxy-tls/quic-host-key.b64",
            "configs/oxibelt-fixture/cert/privkey.pem",
            "configs/oxibelt-fixture/cert/keysigner-token.b64",
        ):
            self.assertFalse((artifact / relative).exists(), relative)
        receipt = json.loads(
            (artifact / "restricted-receipt.json").read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["status"], "removed")

    def test_aggregate_failure_is_retained_and_gets_eof(self) -> None:
        campaign = self.seed_full_benchmark()
        result = self.invoke(
            "aggregate", campaign, env={"FAKE_AGGREGATE_MODE": "command-fail"}
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        records = [
            json.loads(line)
            for line in self.aggregate_record.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record["stdin_bytes"] == 0 for record in records))
        manifest = json.loads(
            (campaign / "campaign-manifest.json").read_text(encoding="utf-8")
        )
        self.assertTrue(all(record["exit_code"] != 0 for record in manifest["aggregates"]))

    def test_aggregate_timeout_is_retained_and_fails_closed(self) -> None:
        campaign = self.seed_full_benchmark(campaign=self.root / "aggregate-timeout")
        result = self.invoke(
            "aggregate",
            campaign,
            env={
                "FAKE_TIMEOUT_FORCE": "aggregate",
                "FAKE_AGGREGATE_SLEEP_SECONDS": "5",
            },
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            len(self.aggregate_record.read_text(encoding="utf-8").splitlines()),
            len(TARGETS),
        )
        manifest = json.loads(
            (campaign / "campaign-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["status"], "aggregate-failed")
        self.assertEqual(len(manifest["aggregates"]), len(TARGETS))
        for aggregate in manifest["aggregates"]:
            self.assertEqual(aggregate["command_exit_code"], 124)
            self.assertEqual(aggregate["exit_code"], 124)
            self.assertEqual(aggregate["status"], "timeout")
            self.assertTrue(aggregate["timed_out"])
            self.assertEqual(aggregate["timeout_scope"], "aggregate")
            self.assertEqual(aggregate["timeout_seconds"], 900)


if __name__ == "__main__":
    unittest.main()
