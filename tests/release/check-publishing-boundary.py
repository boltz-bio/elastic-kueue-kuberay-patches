"""Test publishing permissions, immutable actions and trusted event guards."""

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted(
    [*ROOT.glob(".github/workflows/*.yaml"), *ROOT.glob(".github/workflows/*.yml")]
)
SUCCESSFUL_RELEASE = {
    "inputs.release-tag": "ray-vfixture",
    "needs.release-please.outputs.releases_created": "true",
    "needs.release-please.outputs.ray_release_created": "true",
    "needs.release-please.result": "success",
    "needs.ray-wheels.result": "success",
}


def evaluate(condition: str, context: dict[str, str]) -> bool:
    """Evaluate the small expression vocabulary used by these actual job guards."""
    values: dict[str, str] = {}

    def variable(match: re.Match[str]) -> str:
        key = f"value_{len(values)}"
        values[key] = context[match.group()]
        return key

    expression = (
        re.sub(
            r"\b(?:github|needs|inputs)(?:\.[a-zA-Z_][a-zA-Z0-9_-]*)+",
            variable,
            condition,
        )
        .replace("&&", " and ")
        .replace("||", " or ")
    )

    def visit(node: ast.AST) -> object:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "true":
                return True
            if node.id == "false":
                return False
            return values[node.id]
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(visit(value) for value in node.values)
            if isinstance(node.op, ast.Or):
                return any(visit(value) for value in node.values)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = visit(node.left), visit(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            arguments = [visit(argument) for argument in node.args]
            if node.func.id == "always" and not arguments:
                return True
            if node.func.id == "fromJSON" and len(arguments) == 1:
                assert isinstance(arguments[0], str)
                return json.loads(arguments[0])
            if node.func.id == "contains" and len(arguments) == 2:
                assert isinstance(arguments[0], list)
                return arguments[1] in arguments[0]
        raise AssertionError(f"Unsupported guard syntax: {ast.dump(node)}")

    return bool(visit(ast.parse(expression, mode="eval").body))


fixtures = [
    (
        "main-push",
        "boltz-bio/elastic-kueue-kuberay-patches",
        "refs/heads/main",
        "push",
        True,
    ),
    (
        "main-dispatch",
        "boltz-bio/elastic-kueue-kuberay-patches",
        "refs/heads/main",
        "workflow_dispatch",
        True,
    ),
    ("other-repository", "example/project", "refs/heads/main", "push", False),
    (
        "fork-pull-request",
        "boltz-bio/elastic-kueue-kuberay-patches",
        "refs/pull/1/merge",
        "pull_request",
        False,
    ),
    (
        "feature-dispatch",
        "boltz-bio/elastic-kueue-kuberay-patches",
        "refs/heads/feature",
        "workflow_dispatch",
        False,
    ),
    (
        "tag-push",
        "boltz-bio/elastic-kueue-kuberay-patches",
        "refs/tags/example",
        "push",
        False,
    ),
    (
        "privileged-pr-event",
        "boltz-bio/elastic-kueue-kuberay-patches",
        "refs/heads/main",
        "pull_request_target",
        False,
    ),
    (
        "chained-workflow",
        "boltz-bio/elastic-kueue-kuberay-patches",
        "refs/heads/main",
        "workflow_run",
        False,
    ),
]


def check_source(filename: str, source: str) -> list[str]:
    """Reject unsupported declaration forms before finding every guarded write job."""
    for line in source.splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            assert re.match(r"[a-zA-Z_][\w-]*:", line), "Unsupported workflow key"
    default = re.search(r"^permissions:\n((?:  [^\n]+\n)+)", source, re.M)
    assert default and default.group(1) == "  contents: read\n"
    assert len(re.findall(r"^jobs:$", source, re.M)) == 1
    assert not re.search(r"^\s*<<\s*:", source, re.M), "YAML merge keys are unsupported"
    job_source = source.split("\njobs:\n", 1)[1]
    for line in job_source.splitlines():
        if (
            line.startswith("  ")
            and not line.startswith("   ")
            and line.strip()
            and not line.lstrip().startswith("#")
        ):
            assert re.fullmatch(r"  [a-zA-Z_][\w-]*:", line), (
                "Unsupported job declaration"
            )
    for action in re.findall(r"\buses: ([^\s]+)", source):
        assert action.startswith("./") or re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)
    consumed_permissions = 1  # The explicit read-only workflow default above.
    checked = []
    for match in re.finditer(
        r"^  ([a-zA-Z_][\w-]*):\n(.*?)(?=^  [a-zA-Z_][\w-]*:\n|\Z)",
        job_source,
        re.M | re.S,
    ):
        job, body = match.groups()
        for line in body.splitlines():
            if (
                line.startswith("    ")
                and not line.startswith("     ")
                and line.strip()
                and not line.lstrip().startswith("#")
            ):
                assert re.match(r"    [a-zA-Z_][\w-]*:", line), "Unsupported job key"
        declarations = re.findall(
            r"^    (?:permissions|[\"']permissions[\"'])\s*:[^\n]*$", body, re.M
        )
        assert len(declarations) <= 1, "Duplicate job permission declarations"
        if not declarations:
            continue
        assert declarations == ["    permissions:"], (
            "Unsupported permission declaration"
        )
        permissions = re.search(
            r"^    permissions:\n((?:      [^\n]*\n|[ \t]*\n)+)", body, re.M
        )
        assert permissions, "Missing permission mapping"
        scopes = []
        for line in permissions.group(1).splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            entry = re.fullmatch(r"      [a-z][a-z-]*: (read|write|none)", line)
            assert entry, "Unsupported permission mapping value"
            scopes.append(entry.group(1))
        assert scopes
        consumed_permissions += 1
        if "write" not in scopes:
            continue
        condition = re.search(r"^    if: \$\{\{ (.+) \}\}$", body, re.M)
        assert condition, (filename, job, "write job lacks an event guard")
        condition = condition.group(1)
        for name, repository, ref, event, expected in fixtures:
            context = {
                **SUCCESSFUL_RELEASE,
                "github.repository": repository,
                "github.ref": ref,
                "github.event_name": event,
            }
            assert evaluate(condition, context) == expected, (filename, job, name)
        weaker = condition.replace("github.ref == 'refs/heads/main'", "true")
        assert weaker != condition
        context = {
            **SUCCESSFUL_RELEASE,
            "github.repository": "boltz-bio/elastic-kueue-kuberay-patches",
            "github.ref": "refs/heads/feature",
            "github.event_name": "workflow_dispatch",
        }
        assert evaluate(weaker, context), (
            filename,
            job,
            "ineffective negative control",
        )
        checked.append(f"{filename}:{job}")
    declarations = re.findall(
        r"^\s*(?:permissions|[\"']permissions[\"'])\s*:", source, re.M
    )
    assert len(declarations) == consumed_permissions, (
        "Unconsumed permission declaration"
    )
    return checked


sources = {workflow.name: workflow.read_text() for workflow in WORKFLOWS}
checked = [
    job
    for filename, source in sources.items()
    for job in check_source(filename, source)
]
assert checked
filename, job = checked[0].split(":", 1)
source = sources[filename]
pattern = r"^  " + re.escape(job) + r":\n.*?(?=^  [a-zA-Z_][\w-]*:\n|\Z)"
block = re.search(pattern, source, re.M | re.S).group()
unguarded = re.sub(r"^    if:.*\n", "", block, count=1, flags=re.M)
permissions = re.search(
    r"^    permissions:\n((?:      [^\n]*\n)+)", unguarded, re.M
).group()
mutations = {
    "unguarded-block-permissions": unguarded,
    "unguarded-inline-permissions": unguarded.replace(
        permissions, "    permissions: {contents: read, packages: write}\n"
    ),
    "unguarded-write-all": unguarded.replace(
        permissions, "    permissions: write-all\n"
    ),
    "unguarded-inline-job": "  "
    + job
    + ": {runs-on: ubuntu-latest, permissions: {packages: write}, steps: []}\n",
    "unguarded-quoted-permissions": unguarded.replace(
        "    permissions:", "    'permissions':"
    ),
    "unguarded-merged-permissions": unguarded.replace(
        permissions, "    <<: *write-permissions\n"
    ),
    "unguarded-explicit-permissions-key": unguarded.replace(
        permissions, "    ? permissions\n    : write-all\n"
    ),
    "unguarded-multiline-permission-value": unguarded.replace(
        permissions, "    permissions:\n      packages: >-\n        write\n"
    ),
    "unguarded-duplicate-permissions": unguarded.replace(
        permissions, permissions + "    permissions:\n      packages: write\n"
    ),
}
for name, mutated in mutations.items():
    candidate = source.replace(block, mutated, 1)
    try:
        check_source(filename, candidate)
    except AssertionError:
        pass
    else:
        raise AssertionError(f"Unsafe permission mutation was accepted: {name}")
print(
    json.dumps(
        {
            "guarded_write_jobs": checked,
            "event_cases": len(fixtures),
            "branch_guard_negative_controls": len(checked),
            "unsafe_permission_mutations_rejected": list(mutations),
        }
    )
)
