"""Terraform drafter eval: the parts that are code, on tricky inputs.

  checks       the reviewer-facing checks on drafted Terraform: each case says exactly which
               checks must warn, so both misses and false alarms fail the gate
  hard limits  submit_draft refuses paths outside teams/<team>/, other suffixes, too many
               files, and decisions without what they need
  binding      the approval hash changes when any byte of any file changes

The model's judgement (reuse vs new, asking a question) is covered by the end-to-end tests
with scripted models (tests/test_infra.py); a live-model run is a manual check.

    python evals/infra_eval.py           # exit 1 if any case fails
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from audit_agent.db import Scope  # noqa: E402
from audit_agent.tools import infra as _infra_tools  # noqa: E402,F401  (registers submit_draft)
from audit_agent.tools.base import REGISTRY, ToolContext, ToolError  # noqa: E402
from fix_agent import infra_checks  # noqa: E402
from fix_agent.infra_write import files_hash  # noqa: E402

TEAM = "web"
D = f"teams/{TEAM}/"
TAG = f'tags = {{ team = "{TEAM}" }}'

CHECK = {"files": f"Files only under {D}", "parse": "HCL parses", "tags": f'Resources tagged team = "{TEAM}"',
         "root": "No provider/backend in the team folder", "secret": "No hard-coded secrets",
         "wildcard": 'No "*" IAM actions', "public": "No public access"}

# (name, files as {path: content}, checks that must warn)
CHECK_CASES = [
    ("clean module + tagged queue",
     {D + "main.tf": f'module "b" {{\n  source = "../../modules/s3"\n  name = "x"\n}}\n'
                     f'resource "aws_sqs_queue" "q" {{\n  name = "q"\n  {TAG}\n}}\n'}, set()),
    ("untagged resource", {D + "q.tf": 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n'}, {"tags"}),
    ("wrong team in tag", {D + "q.tf": 'resource "aws_sqs_queue" "q" {\n  tags = { team = "data" }\n}\n'}, {"tags"}),
    ("sub-resources need no tags",
     {D + "b.tf": f'resource "aws_s3_bucket" "b" {{\n  bucket = "b"\n  {TAG}\n}}\n'
                  'resource "aws_s3_bucket_versioning" "v" {\n  bucket = aws_s3_bucket.b.id\n'
                  '  versioning_configuration {\n    status = "Enabled"\n  }\n}\n'
                  'resource "aws_s3_bucket_public_access_block" "p" {\n  bucket = aws_s3_bucket.b.id\n'
                  '  block_public_acls = true\n  block_public_policy = true\n}\n'}, set()),
    ("data sources ignored for tags", {D + "d.tf": 'data "aws_caller_identity" "me" {}\n'}, set()),
    ("provider block", {D + "p.tf": 'provider "aws" {\n  region = "ap-southeast-2"\n}\n'}, {"root"}),
    ("backend block", {D + "b.tf": 'terraform {\n  backend "s3" {\n    bucket = "x"\n  }\n}\n'}, {"root"}),
    ("required_providers alone is fine",
     {D + "v.tf": 'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}\n'}, set()),
    ("hard-coded password",
     {D + "db.tf": f'resource "aws_db_instance" "d" {{\n  password = "hunter22hunter"\n  {TAG}\n}}\n'}, {"secret"}),
    ("password from a variable",
     {D + "db.tf": f'resource "aws_db_instance" "d" {{\n  password = var.db_password\n  {TAG}\n}}\n'}, set()),
    ("password interpolated",
     {D + "db.tf": f'resource "aws_db_instance" "d" {{\n  password = "${{var.p}}"\n  {TAG}\n}}\n'}, set()),
    ("IAM action = \"*\" (HCL)",
     {D + "i.tf": 'data "aws_iam_policy_document" "p" {\n  statement {\n    actions = ["*"]\n'
                  '    resources = ["*"]\n  }\n}\n'}, {"wildcard"}),
    ("IAM service:* (jsonencode)",
     {D + "i.tf": 'resource "aws_iam_policy" "p" {\n  policy = jsonencode({ Statement = [{ Action = "s3:*",'
                  ' Effect = "Allow", Resource = "*" }] })\n  ' + TAG + '\n}\n'}, {"wildcard"}),
    ("IAM specific actions with resources *",
     {D + "i.tf": 'data "aws_iam_policy_document" "p" {\n  statement {\n    actions = ["s3:GetObject"]\n'
                  '    resources = ["*"]\n  }\n}\n'}, set()),
    ("public-read ACL",
     {D + "b.tf": f'resource "aws_s3_bucket_acl" "a" {{\n  acl = "public-read"\n  {TAG}\n}}\n'}, {"public"}),
    ("open security group",
     {D + "sg.tf": f'resource "aws_security_group" "s" {{\n  ingress {{\n    from_port = 22\n    to_port = 22\n'
                   f'    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }}\n  {TAG}\n}}\n'}, {"public"}),
    ("public access block turned off",
     {D + "b.tf": 'resource "aws_s3_bucket_public_access_block" "p" {\n  bucket = "b"\n'
                  '  block_public_acls = false\n}\n'}, {"public"}),
    ("broken HCL", {D + "x.tf": 'resource "aws_sqs_queue" "q" {\n  name = \n'}, {"parse"}),
    ("README only", {D + "README.md": "# web stack\n"}, set()),
    ("file outside the team folder", {"teams/data/x.tf": f'resource "aws_sqs_queue" "q" {{\n  {TAG}\n}}\n'}, {"files"}),
]


def check_cases() -> list[tuple[str, bool, str]]:
    out = []
    for name, files, want in CHECK_CASES:
        got = infra_checks.run([{"path": p, "content": c} for p, c in files.items()], TEAM)
        failing = {k for k, label in CHECK.items() for c in got if c["name"] == label and not c["ok"]}
        detail = ", ".join(sorted(failing)) or "all ok"
        if failing != want:
            detail += f"  (expected: {', '.join(sorted(want)) or 'all ok'})"
        out.append((f"check: {name}", failing == want, detail))
    return out


def limit_cases() -> list[tuple[str, bool, str]]:
    tool = REGISTRY["submit_draft"]
    ctx = ToolContext(scope=Scope(user_id="worker:infra", team_ids=(TEAM,), role="worker"), db=None, mode="infra")
    f = lambda path, content="x = 1\n": {"path": path, "content": content}  # noqa: E731
    cases = [  # (name, args, None = accepted | substring of the refusal)
        ("accepts a team file", {"decision": "new", "files": [f(D + "q.tf")]}, None),
        ("accepts reuse with no files", {"decision": "reuse"}, None),
        ("refuses ../ escape", {"decision": "new", "files": [f(D + "../data/q.tf")]}, "bad path"),
        ("refuses another team", {"decision": "new", "files": [f("teams/data/q.tf")]}, "must be under"),
        ("refuses a module edit", {"decision": "new", "files": [f("modules/s3/main.tf")]}, "must be under"),
        ("refuses prefix trick", {"decision": "new", "files": [f("teams/web2/q.tf")]}, "must be under"),
        ("refuses a script", {"decision": "new", "files": [f(D + "run.sh")]}, "only .tf"),
        ("refuses a duplicate", {"decision": "new", "files": [f(D + "a.tf"), f(D + "a.tf")]}, "twice"),
        ("refuses 9 files", {"decision": "new", "files": [f(f"{D}{i}.tf") for i in range(9)]}, "Invalid arguments"),
        ("new needs files", {"decision": "new"}, "at least one file"),
        ("refuse has no files", {"decision": "refuse", "files": [f(D + "q.tf")]}, "must not include"),
        ("need_input needs a question", {"decision": "need_input"}, "needs a question"),
    ]
    out = []
    for name, args, want in cases:
        args = {"reasoning": "Checked conventions, history and the repo first.", **args}
        try:
            data = tool.handler(ctx, tool.parse(json.dumps(args))).data
            ok = want is None
            detail = f"accepted ({data['decision']}, {len(data['files'])} files)"
        except ToolError as exc:
            ok = want is not None and want in str(exc)
            detail = f"refused: {str(exc)[:70]}"
        out.append((f"limit: {name}", ok, detail))
    return out


def binding_cases() -> list[tuple[str, bool, str]]:
    a = [{"path": D + "a.tf", "content": 'resource "x" "y" {}\n'}, {"path": D + "b.tf", "content": "# b\n"}]
    h = files_hash(a)
    reordered_keys = [{"content": x["content"], "path": x["path"]} for x in a]
    one_byte = [a[0], {"path": D + "b.tf", "content": "# b \n"}]
    renamed = [a[0], {"path": D + "c.tf", "content": "# b\n"}]
    extra = [*a, {"path": D + "c.tf", "content": ""}]
    return [("binding: same files, same hash", files_hash(reordered_keys) == h, h[:12]),
            ("binding: one byte changes it", files_hash(one_byte) != h, files_hash(one_byte)[:12]),
            ("binding: a rename changes it", files_hash(renamed) != h, files_hash(renamed)[:12]),
            ("binding: an added file changes it", files_hash(extra) != h, files_hash(extra)[:12])]


def main() -> int:
    rows = check_cases() + limit_cases() + binding_cases()
    for name, ok, detail in rows:
        print(f"{'ok ' if ok else 'FAIL'} {name:<44} {detail}")
    passed = sum(ok for _, ok, _ in rows)
    print(f"\nterraform drafter: {passed}/{len(rows)} passed")
    print("GATE PASSED" if passed == len(rows) else "GATE FAILED")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
