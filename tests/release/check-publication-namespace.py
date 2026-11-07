"""Verify resolved publication ownership and actual publish-task arguments without building images or contacting a registry."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[2]
config = tomllib.loads((ROOT / "mise.toml").read_text())
repository = os.environ.get(
    "GITHUB_REPOSITORY", "boltz-bio/elastic-kueue-kuberay-patches"
)
owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "boltz-bio")
assert os.environ["PUBLISH_REPOSITORY"] == repository
assert os.environ["PUBLISH_OWNER"] == owner
wheel_url = (
    f"https://github.com/{repository}/releases/download/ray-v"
    + os.environ["RAY_PATCH_VERSION"]
)
assert os.environ["RAY_WHEEL_BASE_URL"] == wheel_url

with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    binary = directory / "docker"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "with Path(os.environ['PUBLICATION_CALLS']).open('a') as output:\n"
        "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    binary.chmod(0o755)
    shim = directory / "mise"
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import os, subprocess, sys\n"
        "assert sys.argv[1:] == ['run', 'ray:wheel-args']\n"
        "sys.exit(subprocess.run(['bash', '-eu', '-c', "
        "os.environ['PUBLICATION_WHEEL_ARGS']]).returncode)\n"
    )
    shim.chmod(0o755)
    calls = directory / "calls.jsonl"
    environment = {
        **os.environ,
        "PATH": str(directory) + os.pathsep + os.environ["PATH"],
        "PUBLICATION_CALLS": str(calls),
        "PUBLICATION_WHEEL_ARGS": config["tasks"]["ray:wheel-args"]["run"],
        "RAY_INSTALL_WHEEL": "1",
        "RAY_WHEEL_DIR": "",
    }
    environment.pop("RAY_WHEEL_SERVER_URL", None)
    publishers = {
        name: task
        for name, task in config["tasks"].items()
        if name.startswith("publish:")
    }
    for name, task in publishers.items():
        subprocess.run(
            ["bash", "-eu", "-c", task["run"]],
            cwd=ROOT,
            env=environment,
            check=True,
        )
    commands = [json.loads(line) for line in calls.read_text().splitlines()]
    assert len(commands) == len(publishers)
    tags = []
    for command in commands:
        assert command[:2] == ["buildx", "build"]
        assert "--push" in command
        command_tags = [
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "-t"
        ]
        assert command_tags
        assert all(tag.startswith(f"ghcr.io/{owner}/") for tag in command_tags)
        tags.extend(command_tags)
    ray_commands = [
        command
        for command in commands
        if any(argument.startswith(f"ghcr.io/{owner}/ray:") for argument in command)
    ]
    assert len(ray_commands) == 1
    assert f"RAY_WHEEL_BASE_URL={wheel_url}" in ray_commands[0]

print(
    json.dumps(
        {
            "repository": repository,
            "registry_owner": owner,
            "publish_tasks": len(publishers),
            "tags_checked": len(tags),
        }
    )
)
