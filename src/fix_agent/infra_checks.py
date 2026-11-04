"""Checks on drafted Terraform, run by code after the model drafts. They never block: the
results go to the reviewer next to the diff (the requester asked for a draft; the lead
decides). Each check is {"name", "ok", "detail"}."""
from __future__ import annotations

import re

import hcl2

TAGGABLE_PREFIXES = ("aws_",)
UNTAGGABLE = {"aws_s3_bucket_public_access_block", "aws_s3_bucket_versioning", "aws_s3_bucket_policy",
              "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_lifecycle_configuration",
              "aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_policy_document",
              "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_sns_topic_subscription",
              "aws_lambda_permission", "aws_cloudwatch_log_stream", "aws_route", "aws_security_group_rule",
              "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"}
SECRET_RE = re.compile(r'(?i)\b(password|secret|token|api_key|access_key|private_key)\s*=\s*"(?!\$\{)[^"]{6,}"')
WILDCARD_RE = re.compile(r'(?i)("?\bactions?"?\s*[:=]\s*\[?\s*"\*"|"[a-z0-9-]+:\*"|"\*:\*")')
PUBLIC_RE = re.compile(r'(?i)(acl\s*=\s*"public-read|block_public_(acls|policy)\s*=\s*false|'
                       r'restrict_public_buckets\s*=\s*false|cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\])')


def _unq(v):
    return v.strip('"') if isinstance(v, str) else v


def _blocks(doc: dict, kind: str):
    """(type, name, body) for every block of a kind, for python-hcl2 7.x and 8.x output."""
    for entry in doc.get(kind, []):
        for typ, named in entry.items():
            if kind in ("resource", "data"):
                for name, body in (named or {}).items():
                    yield _unq(typ), _unq(name), body if isinstance(body, dict) else {}
            else:
                yield _unq(typ), "", named if isinstance(named, dict) else {}


def run(files: list[dict], team: str) -> list[dict]:
    checks: list[dict] = []
    base = f"teams/{team}/"
    tf = [f for f in files if f["path"].endswith((".tf", ".tfvars"))]

    outside = [f["path"] for f in files if not f["path"].startswith(base)]
    checks.append({"name": f"Files only under {base}", "ok": not outside,
                   "detail": ", ".join(outside) if outside else f"{len(files)} file(s)"})

    parsed, errors = {}, []
    for f in tf:
        try:
            parsed[f["path"]] = hcl2.loads(f["content"])
        except Exception as exc:  # noqa: BLE001 - any parse failure is reported, not raised
            errors.append(f"{f['path']}: {str(exc).splitlines()[0][:140]}")
    checks.append({"name": "HCL parses", "ok": not errors,
                   "detail": "; ".join(errors) if errors else (f"{len(tf)} Terraform file(s)" if tf else "no .tf files")})

    untagged, roots = [], []
    for path, doc in parsed.items():
        for typ, name, body in _blocks(doc, "resource"):
            if typ.startswith(TAGGABLE_PREFIXES) and typ not in UNTAGGABLE:
                tags = body.get("tags")
                tags = tags[0] if isinstance(tags, list) and tags else tags
                if not isinstance(tags, dict) or _unq(tags.get("team")) != team:
                    untagged.append(f"{typ}.{name}")
        for typ, _n, _body in _blocks(doc, "provider"):
            roots.append(f"{path}: provider {typ}")
        # A `terraform` block has no label: its entries are bodies ({"backend": [...], ...}).
        for body in doc.get("terraform", []):
            if isinstance(body, dict) and "backend" in body:
                kinds = [_unq(k) for b in body["backend"] if isinstance(b, dict) for k in b if k != "__is_block__"]
                roots.append(f"{path}: backend {', '.join(kinds)}".strip())
    checks.append({"name": f'Resources tagged team = "{team}"', "ok": not untagged,
                   "detail": ("missing on " + ", ".join(untagged[:8])) if untagged else "all tagged"})
    checks.append({"name": "No provider/backend in the team folder", "ok": not roots,
                   "detail": "; ".join(roots[:4]) if roots else "uses the repo's root configuration"})

    text = "\n".join(f["content"] for f in tf)
    for name, rx in (("No hard-coded secrets", SECRET_RE), ('No "*" IAM actions', WILDCARD_RE),
                     ("No public access", PUBLIC_RE)):
        hits = sorted({m.group(0)[:60] for m in rx.finditer(text)})
        checks.append({"name": name, "ok": not hits, "detail": "; ".join(hits[:3]) if hits else "none found"})
    return checks
