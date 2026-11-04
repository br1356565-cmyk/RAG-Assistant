"""The Terraform drafter end to end: memory -> repo -> draft -> code checks -> (question) ->
lead approval bound to the files -> PR; rejection -> proposed convention -> recalled next time."""
import json

import psycopg
import pytest

from audit_agent.config import Settings
from audit_agent.db import Scope
from audit_agent.handlers import api
from audit_agent.handlers.deps import Deps

from conftest import DBNAME, GROWTH, UK, FakeLLM, _admin_dsn, call, say, tools

LEAD = Scope(user_id="lead-growth", team_ids=("growth_engineering",), role="team_lead")
UK_LEAD = Scope(user_id="lead-uk", team_ids=("uk_engineering",), role="team_lead")
TEAM = "growth_engineering"
GOOD_TF = ('module "exports" {\n  source = "../../modules/s3"\n  name   = "growth-exports"\n}\n\n'
           'resource "aws_sqs_queue" "jobs" {\n  name = "growth-jobs"\n  tags = { team = "growth_engineering" }\n}\n')


def owner(sql, params=()):
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        cur = c.execute(sql, params or None)
        return cur.fetchall() if cur.description else []


class InfraRepo:
    org = "x"
    files = {"README.md": "# infra\nUse modules/ for buckets.", "modules/s3/main.tf": 'variable "name" {}\n',
             f"teams/{TEAM}/main.tf": '# growth stack\n'}

    def list_dir(self, repo, path):
        assert repo == "infra-repo"
        prefix = (path.strip("/") + "/") if path else ""
        seen = {}
        for p in self.files:
            if p.startswith(prefix):
                head = p[len(prefix):].split("/", 1)
                seen[head[0]] = {"name": head[0], "path": prefix + head[0], "type": "dir" if len(head) > 1 else "file"}
        return list(seen.values()) or None

    def read_file(self, repo, path):
        return self.files.get(path)


class Writer:
    def __init__(self):
        self.calls = []

    def default_branch(self, repo):
        return "main"

    def branch_sha(self, repo, b):
        return "sha"

    def file_sha(self, repo, path, ref):
        return None

    def create_branch(self, repo, name, sha):
        self.calls.append(("branch", repo, name))

    def put_file(self, repo, path, content, branch, message, sha):
        self.calls.append(("put", repo, path, content))

    def open_pull(self, repo, head, base, title, body):
        self.calls.append(("pr", repo, title, body))
        return f"https://github.com/x/{repo}/pull/3"


@pytest.fixture()
def drafter(db, monkeypatch):
    from types import SimpleNamespace

    from langgraph.checkpoint.postgres import PostgresSaver
    from psycopg.rows import dict_row

    from audit_agent.fix_client import LocalFixClient
    from audit_agent.tools import tools_for
    from fix_agent.infra_graph import InfraDeps
    from fix_agent.infra_service import InfraService
    from fix_agent.infra_write import open_infra_pr

    monkeypatch.setenv("INFRA_REPO", "infra-repo")
    host = db._dsn.split("host=")[1].split()[0]
    port = db._dsn.split("port=")[1].split()[0]
    conn = psycopg.connect(f"host={host} port={port} user=app_login dbname={DBNAME}", autocommit=True, row_factory=dict_row)
    repo, writer, llm = InfraRepo(), Writer(), FakeLLM([])
    deps = InfraDeps(db=db, tools=lambda: tools_for("infra", SimpleNamespace(gateway=None, aws=None, ssm=None, fix_client=None)),
                     llm_for=lambda teams: llm, model="m", read_infra=lambda scope, path: repo.read_file("infra-repo", path),
                     open_pr=lambda scope, rid: open_infra_pr(db, scope, rid, writer=writer, repo="infra-repo"),
                     repo="infra-repo", github=repo)
    client = LocalFixClient(service=None, infra=InfraService(deps, PostgresSaver(conn)))
    yield SimpleNamespace(client=client, llm=llm, writer=writer,
                          deps=lambda: Deps(settings=Settings.from_env(), db=db, verifier=None, llm_for=None,
                                            github=None, fix_client=client))
    conn.close()


def submit(decision="new", files=None, question=None, reasoning="Checked conventions, past requests and modules/s3."):
    args = {"decision": decision, "reasoning": reasoning, "confidence": "high", "files": files or []}
    if question:
        args["question"] = question
    return tools(call("submit_draft", args, id=f"s{decision}"))


def research():
    return [tools(call("recall_conventions", {}), call("similar_requests", {"query": "s3 bucket exports"})),
            tools(call("list_infra_files", {"path": ""}), call("read_infra_file", {"path": "modules/s3/main.tf"}))]


def test_draft_review_approve_pr(db, drafter):
    drafter.llm.script = [*research(), submit(files=[{"path": f"teams/{TEAM}/exports.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    status, out = api.infra_request(deps, GROWTH, {"request": "An S3 bucket for nightly exports, plus a jobs queue"})
    assert status == 200 and out["status"] == "awaiting_approval" and out["decision"] == "new"
    rid = out["request_id"]
    detail = api.infra_detail(deps, GROWTH, {"id": rid})[1]
    assert detail["files"][0]["path"] == f"teams/{TEAM}/exports.tf" and "--- /dev/null" in detail["diff"]
    assert all(c["ok"] for c in detail["checks"]), detail["checks"]
    assert "Reading modules/s3/main.tf" not in detail["steps"] and len(detail["steps"]) >= 4
    assert api.infra_decide(deps, GROWTH, {"request_id": rid, "decision": "approved"})[0] == 403   # members can't
    status, out = api.infra_decide(deps, LEAD, {"request_id": rid, "decision": "approved"})
    assert status == 200 and out["status"] == "opened" and out["pr_url"].endswith("/pull/3")
    kinds = [c[0] for c in drafter.writer.calls]
    assert kinds == ["branch", "put", "pr"] and drafter.writer.calls[1][2] == f"teams/{TEAM}/exports.tf"
    assert "infra(growth_engineering)" in drafter.writer.calls[2][2] and "approved by lead-growth" in drafter.writer.calls[2][3]


def test_asks_the_requester_then_drafts(db, drafter):
    drafter.llm.script = [*research(), submit("need_input", question="Which environment: dev or prod?"),
                          submit(files=[{"path": f"teams/{TEAM}/queue.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    _, out = api.infra_request(deps, GROWTH, {"request": "A queue for the image resize jobs"})
    assert out["status"] == "needs_input" and out["question"] == "Which environment: dev or prod?"
    assert api.infra_answer(deps, UK, {"request_id": out["request_id"], "answer": "prod"})[0] == 409   # not visible
    status, out2 = api.infra_answer(deps, GROWTH, {"request_id": out["request_id"], "answer": "prod, 14 day retention"})
    assert status == 200 and out2["status"] == "awaiting_approval"
    redraft = drafter.llm.calls[-1]["messages"][1]["content"]
    assert "Which environment" in redraft and "prod, 14 day retention" in redraft


def test_rejection_becomes_a_convention_the_next_draft_recalls(db, drafter):
    drafter.llm.script = [*research(), submit(files=[{"path": f"teams/{TEAM}/b.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    rid = api.infra_request(deps, GROWTH, {"request": "A bucket for marketing images"})[1]["request_id"]
    assert api.infra_decide(deps, LEAD, {"request_id": rid, "decision": "rejected"})[0] == 400      # needs a reason
    status, out = api.infra_decide(deps, LEAD, {"request_id": rid, "decision": "rejected",
                                                "reason": "Buckets must enable versioning and use modules/s3 only"})
    assert status == 200 and drafter.writer.calls == []                                            # GitHub untouched
    conv = api.conventions(deps, GROWTH, {})[1]["conventions"]
    assert conv[0]["status"] == "proposed" and conv[0]["source"] == "rejection"
    assert api.convention_decide(deps, GROWTH, {"id": conv[0]["id"], "decision": "active"})[0] in (403, 404)
    assert api.convention_decide(deps, LEAD, {"id": conv[0]["id"], "decision": "active"})[1]["status"] == "active"

    drafter.llm.script = [*research(), submit(files=[{"path": f"teams/{TEAM}/c.tf", "content": GOOD_TF}])]
    api.infra_request(deps, GROWTH, {"request": "Another bucket for exports"})
    recalled = [m["content"] for m in drafter.llm.calls[-1]["messages"] if m["role"] == "tool"]
    assert any("Buckets must enable versioning" in r for r in recalled)                            # memory
    assert any("marketing images" in r and "rejected_because" in r for r in recalled)               # history


def test_hard_limits_and_soft_checks(db, drafter):
    bad = 'provider "aws" { region = "x" }\nresource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}\n'
    drafter.llm.script = [submit(files=[{"path": "modules/s3/hack.tf", "content": bad}]),          # refused by the tool
                          submit(files=[{"path": f"teams/{TEAM}/b.tf", "content": bad}])]            # allowed, flagged
    deps = drafter.deps()
    rid = api.infra_request(deps, GROWTH, {"request": "A public bucket for the website"})[1]["request_id"]
    first = [m["content"] for m in drafter.llm.calls[1]["messages"] if m["role"] == "tool"][-1]
    assert "files must be under teams/growth_engineering/" in first
    detail = api.infra_detail(deps, GROWTH, {"id": rid})[1]
    failing = {c["name"] for c in detail["checks"] if not c["ok"]}
    assert detail["status"] == "awaiting_approval"                                                 # warnings, not blocks
    assert {"No public access", "No provider/backend in the team folder", 'Resources tagged team = "growth_engineering"'} <= failing


def test_files_changed_after_approval_are_refused(db, drafter):
    from fix_agent.infra_write import WriteRefused, open_infra_pr
    drafter.llm.script = [submit(files=[{"path": f"teams/{TEAM}/q.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    rid = api.infra_request(deps, GROWTH, {"request": "A queue for invoices please"})[1]["request_id"]
    with db.scoped(LEAD) as conn:
        from fix_agent.infra_write import files_hash
        files = conn.execute("select files from infra_requests where id = %s", (rid,)).fetchone()["files"]
        conn.execute("update infra_requests set status='approved', approver='lead-growth', approved_sha256=%s where id=%s",
                     (files_hash(files), rid))
    owner("update infra_requests set files = jsonb_set(files, '{0,content}', '\"evil\"') where id = %s", (rid,))
    worker = Scope(user_id="worker:infra", team_ids=(TEAM,), role="worker")
    with pytest.raises(WriteRefused, match="changed after approval"):
        open_infra_pr(db, worker, rid, writer=drafter.writer, repo="infra-repo")


def test_other_teams_cannot_see_or_decide(db, drafter):
    drafter.llm.script = [submit(files=[{"path": f"teams/{TEAM}/q.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    rid = api.infra_request(deps, GROWTH, {"request": "A queue for invoices please"})[1]["request_id"]
    assert api.infra_detail(deps, UK, {"id": rid})[0] == 404
    assert api.infra_decide(deps, UK_LEAD, {"request_id": rid, "decision": "approved"})[0] == 404
    assert api.infra_list(deps, UK, {})[1]["requests"] == []
    assert api.infra_request(deps, UK, {"request": "x" * 20, "team": TEAM})[0] == 400              # not your team


def test_a2a_routes_infra_actions():
    from audit_agent.scope_token import sign
    from fix_agent.a2a_server import handle

    class Infra:
        def start(self, scope, rid):
            return {"started": rid, "by": scope.user_id}

    key = b"k" * 32
    rid = "00000000-0000-0000-0000-000000000001"
    out = handle(None, key, json.dumps({"action": "infra_start", "request_id": rid, "scope_token": sign(GROWTH, key)}), Infra())
    assert out == {"started": rid, "by": GROWTH.user_id}
    assert "unknown" in handle(None, key, json.dumps({"action": "infra_start", "request_id": rid,
                                                       "scope_token": sign(GROWTH, key)}), None)["error"]


def test_backend_block_is_flagged():
    from fix_agent import infra_checks
    tf = 'terraform {\n  backend "s3" {\n    bucket = "x"\n  }\n}\n'
    got = {c["name"]: c for c in infra_checks.run([{"path": f"teams/{TEAM}/b.tf", "content": tf}], TEAM)}
    assert not got["No provider/backend in the team folder"]["ok"]
    assert "backend s3" in got["No provider/backend in the team folder"]["detail"]
