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
checked = []
for workflow in WORKFLOWS:
    filename = workflow.name
    source = workflow.read_text()
    default = re.search(r"^permissions:\n((?:  [^\n]+\n)+)", source, re.M)
    assert default and default.group(1) == "  contents: read\n"
    for action in re.findall(r"\buses: ([^\s]+)", source):
        assert action.startswith("./") or re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)
    for match in re.finditer(
        r"^  ([a-zA-Z_][\w-]*):\n(.*?)(?=^  [a-zA-Z_][\w-]*:\n|\Z)",
        source,
        re.M | re.S,
    ):
        job, body = match.groups()
        permissions = re.search(r"^    permissions:\n((?:      [^\n]+\n)+)", body, re.M)
        if permissions is None or ": write" not in permissions.group(1):
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
        # Prove the branch-negative fixture observes a removed main-branch guard.
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
assert checked
print(
    json.dumps(
        {
            "guarded_write_jobs": checked,
            "event_cases": len(fixtures),
            "branch_guard_negative_controls": len(checked),
        }
    )
)
