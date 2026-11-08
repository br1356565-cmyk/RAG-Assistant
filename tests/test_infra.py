"""The Terraform drafter end to end, as a security-admin tool: memory -> the chosen repo ->
draft -> code checks -> (question) -> admin approval bound to the files -> PR in that repo;
rejection -> proposed convention -> recalled next time. Nobody else can see or use it."""
import json

import psycopg
import pytest

from audit_agent.config import Settings
from audit_agent.db import Scope
from audit_agent.handlers import api
from audit_agent.handlers.deps import Deps

from conftest import ADMIN, DBNAME, GROWTH, UK, FakeLLM, _admin_dsn, call, tools

LEAD = Scope(user_id="lead-growth", team_ids=("growth_engineering",), role="team_lead")
ADMIN2 = Scope(user_id="admin-two", team_ids=(), role="security_admin")
REPO = "infra-repo"
GOOD_TF = ('module "exports" {\n  source = "../../modules/s3"\n  name   = "growth-exports"\n}\n\n'
           'resource "aws_sqs_queue" "jobs" {\n  name = "growth-jobs"\n  tags = { team = "growth_engineering" }\n}\n')


def owner(sql, params=()):
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        cur = c.execute(sql, params or None)
        return cur.fetchall() if cur.description else []


class InfraRepo:
    org = "x"
    files = {"README.md": "# infra\nUse modules/ for buckets.", "modules/s3/main.tf": 'variable "name" {}\n',
             "envs/prod/main.tf": '# prod stack\n', "teams/uk_engineering/secrets.tf": "# uk"}

    def list_dir(self, repo, path):
        if repo not in (REPO, "other-repo"):
            return None
        prefix = (path.strip("/") + "/") if path else ""
        seen = {}
        for p in self.files:
            if p.startswith(prefix):
                head = p[len(prefix):].split("/", 1)
                seen[head[0]] = {"name": head[0], "path": prefix + head[0], "type": "dir" if len(head) > 1 else "file"}
        return list(seen.values()) or None

    def read_file(self, repo, path):
        return self.files.get(path) if repo in (REPO, "other-repo") else None


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

    monkeypatch.setenv("INFRA_REPO", REPO)
    host = db._dsn.split("host=")[1].split()[0]
    port = db._dsn.split("port=")[1].split()[0]
    conn = psycopg.connect(f"host={host} port={port} user=app_login dbname={DBNAME}", autocommit=True, row_factory=dict_row)
    repo, writer, llm = InfraRepo(), Writer(), FakeLLM([])
    deps = InfraDeps(db=db, tools=lambda: tools_for("infra", SimpleNamespace(gateway=None, aws=None, ssm=None, fix_client=None)),
                     llm_for=lambda teams: llm, model="m", read_infra=lambda scope, target, path: repo.read_file(target, path),
                     open_pr=lambda scope, rid: open_infra_pr(db, scope, rid, writer=writer), repo=REPO, github=repo)
    client = LocalFixClient(service=None, infra=InfraService(deps, PostgresSaver(conn)))
    yield SimpleNamespace(client=client, llm=llm, writer=writer, repo=repo,
                          deps=lambda github=None: Deps(settings=Settings.from_env(), db=db, verifier=None, llm_for=None,
                                                        github=github, fix_client=client))
    conn.close()


def submit(decision="new", files=None, question=None, reasoning="Checked conventions, past requests and modules/s3."):
    args = {"decision": decision, "reasoning": reasoning, "confidence": "high", "files": files or []}
    if question:
        args["question"] = question
    return tools(call("submit_draft", args, id=f"s{decision}"))


def research():
    return [tools(call("recall_conventions", {}), call("similar_requests", {"query": "s3 bucket exports"})),
            tools(call("list_infra_files", {"path": ""}), call("read_infra_file", {"path": "modules/s3/main.tf"}))]


def test_admin_drafts_approves_and_opens_a_pr(db, drafter):
    drafter.llm.script = [*research(), submit(files=[{"path": "envs/prod/exports.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    status, out = api.infra_request(deps, ADMIN, {"request": "An S3 bucket for nightly exports, plus a jobs queue",
                                                  "repo": REPO})
    assert status == 200 and out["status"] == "awaiting_approval" and out["decision"] == "new"
    rid = out["request_id"]
    detail = api.infra_detail(deps, ADMIN, {"id": rid})[1]
    assert detail["repo"] == REPO and detail["files"][0]["path"] == "envs/prod/exports.tf"
    assert "--- /dev/null" in detail["diff"] and all(c["ok"] for c in detail["checks"]), detail["checks"]
    assert "Reading modules/s3/main.tf" not in detail["steps"] and len(detail["steps"]) >= 4
    sha = detail["files_sha256"]
    assert api.infra_decide(deps, ADMIN, {"request_id": rid, "decision": "approved"})[0] == 400        # unseen draft
    assert api.infra_decide(deps, ADMIN, {"request_id": rid, "decision": "approved", "files_sha256": "0" * 64})[0] == 409
    status, out = api.infra_decide(deps, ADMIN, {"request_id": rid, "decision": "approved", "files_sha256": sha})
    assert status == 200 and out["status"] == "opened" and out["pr_url"].endswith(f"/{REPO}/pull/3")  # own draft: allowed
    kinds = [c[0] for c in drafter.writer.calls]
    assert kinds == ["branch", "put", "pr"] and drafter.writer.calls[1][1:3] == (REPO, "envs/prod/exports.tf")
    assert drafter.writer.calls[2][2].startswith("infra: An S3 bucket") and "approved by user-admin" in drafter.writer.calls[2][3]


def test_any_repo_the_admin_names(db, drafter):
    drafter.llm.script = [tools(call("read_infra_file", {"path": "modules/s3/main.tf"})),
                          submit(files=[{"path": "main.tf", "content": GOOD_TF}])]
    deps = drafter.deps(github=drafter.repo)
    assert api.infra_request(deps, ADMIN, {"request": "A queue for invoices please", "repo": "missing-repo"})[0] == 400
    assert api.infra_request(deps, ADMIN, {"request": "A queue for invoices please", "repo": "../etc"})[0] == 400
    rid = api.infra_request(deps, ADMIN, {"request": "A queue for invoices please", "repo": "other-repo"})[1]["request_id"]
    sha = api.infra_detail(deps, ADMIN, {"id": rid})[1]["files_sha256"]
    api.infra_decide(deps, ADMIN, {"request_id": rid, "decision": "approved", "files_sha256": sha})
    assert {c[1] for c in drafter.writer.calls} == {"other-repo"}                                    # the request's repo
    assert api.infra_list(deps, ADMIN, {})[1]["default_repo"] == REPO


def test_only_security_admins_can_use_the_drafter(db, drafter):
    drafter.llm.script = [submit(files=[{"path": "q.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    rid = api.infra_request(deps, ADMIN, {"request": "A queue for invoices please", "repo": REPO})[1]["request_id"]
    for scope in (GROWTH, LEAD, UK):
        assert api.infra_request(deps, scope, {"request": "A queue for invoices please", "repo": REPO})[0] == 403
        assert api.infra_list(deps, scope, {})[0] == 403
        assert api.infra_detail(deps, scope, {"id": rid})[0] == 403
        assert api.infra_decide(deps, scope, {"request_id": rid, "decision": "rejected", "reason": "no thanks"})[0] == 403
        assert api.conventions(deps, scope, {})[0] == 403
        assert api.convention_propose(deps, scope, {"text": "Buckets must be private"})[0] == 403
        with db.scoped(scope) as conn:                                                # and the database agrees
            assert conn.execute("select * from infra_requests").fetchall() == []
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("insert into infra_requests (id, repo, requested_by, request, thread_id) values "
                             "(gen_random_uuid(), 'x', %s, 'sneaky request text', 't')", (scope.user_id,))
    assert api.infra_detail(deps, ADMIN2, {"id": rid})[0] == 200                       # any admin sees all


def test_asks_then_drafts(db, drafter):
    drafter.llm.script = [*research(), submit("need_input", question="Which environment: dev or prod?"),
                          submit(files=[{"path": "envs/prod/queue.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    _, out = api.infra_request(deps, ADMIN, {"request": "A queue for the image resize jobs", "repo": REPO})
    assert out["status"] == "needs_input" and out["question"] == "Which environment: dev or prod?"
    assert api.infra_answer(deps, GROWTH, {"request_id": out["request_id"], "answer": "prod"})[0] == 403
    status, out2 = api.infra_answer(deps, ADMIN, {"request_id": out["request_id"], "answer": "prod, 14 day retention"})
    assert status == 200 and out2["status"] == "awaiting_approval"
    redraft = drafter.llm.calls[-1]["messages"][1]["content"]
    assert "Which environment" in redraft and "prod, 14 day retention" in redraft


def test_rejection_becomes_a_convention_the_next_draft_recalls(db, drafter):
    drafter.llm.script = [*research(), submit(files=[{"path": "b.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    rid = api.infra_request(deps, ADMIN, {"request": "A bucket for marketing images", "repo": REPO})[1]["request_id"]
    assert api.infra_decide(deps, ADMIN, {"request_id": rid, "decision": "rejected"})[0] == 400       # needs a reason
    status, out = api.infra_decide(deps, ADMIN, {"request_id": rid, "decision": "rejected",
                                                 "reason": "Buckets must enable versioning and use modules/s3 only"})
    assert status == 200 and drafter.writer.calls == []                                            # GitHub untouched
    conv = api.conventions(deps, ADMIN, {})[1]["conventions"]
    assert conv[0]["status"] == "proposed" and conv[0]["source"] == "rejection"
    assert api.convention_decide(deps, ADMIN, {"id": conv[0]["id"], "decision": "active"})[1]["status"] == "active"

    drafter.llm.script = [*research(), submit(files=[{"path": "c.tf", "content": GOOD_TF}])]
    api.infra_request(deps, ADMIN, {"request": "Another bucket for exports", "repo": REPO})
    recalled = [m["content"] for m in drafter.llm.calls[-1]["messages"] if m["role"] == "tool"]
    assert any("Buckets must enable versioning" in r for r in recalled)                            # memory
    assert any("marketing images" in r and "rejected_because" in r for r in recalled)               # history


def test_hard_limits_and_soft_checks(db, drafter):
    bad = 'provider "aws" { region = "x" }\nresource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}\n'
    drafter.llm.script = [submit(files=[{"path": "../escape.tf", "content": bad}]),                # refused by the tool
                          submit(files=[{"path": "run.sh", "content": "rm -rf /"}]),               # refused by the tool
                          submit(files=[{"path": "modules/s3/b.tf", "content": bad}])]             # allowed, flagged
    deps = drafter.deps()
    rid = api.infra_request(deps, ADMIN, {"request": "A public bucket for the website", "repo": REPO})[1]["request_id"]
    refusals = [m["content"] for c in drafter.llm.calls[1:3] for m in c["messages"] if m["role"] == "tool"]
    assert any("bad path" in r for r in refusals) and any("only .tf" in r for r in refusals)
    detail = api.infra_detail(deps, ADMIN, {"id": rid})[1]
    failing = {c["name"] for c in detail["checks"] if not c["ok"]}
    assert detail["status"] == "awaiting_approval"                                                 # warnings, not blocks
    assert {"No public access", "No provider/backend blocks", 'Resources have a "team" tag'} <= failing


def test_files_changed_after_approval_are_refused(db, drafter):
    from fix_agent.infra_graph import worker_scope
    from fix_agent.infra_write import WriteRefused, files_hash, open_infra_pr
    drafter.llm.script = [submit(files=[{"path": "q.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    rid = api.infra_request(deps, ADMIN, {"request": "A queue for invoices please", "repo": REPO})[1]["request_id"]
    files = owner("select files from infra_requests where id = %s", (rid,))[0][0]
    owner("update infra_requests set status='approved', approver='user-admin', approved_sha256=%s where id=%s",
          (files_hash(files), rid))
    owner("update infra_requests set files = jsonb_set(files, '{0,content}', '\"evil\"') where id = %s", (rid,))
    with pytest.raises(WriteRefused, match="changed after approval"):
        open_infra_pr(db, worker_scope(), rid, writer=drafter.writer)


def test_people_cannot_rewrite_drafts_only_the_drafter_can(db, drafter):
    from fix_agent.infra_graph import worker_scope
    drafter.llm.script = [submit(files=[{"path": "q.tf", "content": GOOD_TF}])]
    deps = drafter.deps()
    rid = api.infra_request(deps, ADMIN, {"request": "A queue for invoices please", "repo": REPO})[1]["request_id"]
    for sql in ("update infra_requests set files = '[]' where id = %s",
                "update infra_requests set repo = 'other-repo' where id = %s",
                "update infra_requests set checks = '[]' where id = %s",
                "update infra_requests set status = 'opened', pr_url = 'https://evil.example' where id = %s"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with db.scoped(ADMIN) as conn:                                           # even an admin, by hand
                conn.execute(sql, (rid,))
    with db.scoped(worker_scope()) as conn:
        conn.execute("update infra_requests set reasoning = 'the agent may' where id = %s", (rid,))


def test_drafter_reads_anywhere_in_the_request_repo(db):
    from types import SimpleNamespace

    from audit_agent.tools import tools_for
    from audit_agent.tools.base import ToolContext
    from fix_agent.infra_graph import worker_scope

    ctx = ToolContext(scope=worker_scope(), db=db, github=InfraRepo(), mode="infra", extra={"infra_repo": REPO})
    t = {x.name: x for x in tools_for("infra", SimpleNamespace(gateway=None, aws=None, ssm=None, fix_client=None))}
    run = lambda name, args: t[name].handler(ctx, t[name].parse(json.dumps(args))).data  # noqa: E731
    assert run("read_infra_file", {"path": "teams/uk_engineering/secrets.tf"})["content"] == "# uk"
    assert {e["name"] for e in run("list_infra_files", {"path": ""})["entries"]} >= {"modules", "envs", "teams"}
    assert t["similar_requests"].untrusted                                    # people's text is data


def test_the_request_repo_travels_in_the_signed_token(db):
    """Remote (Gateway) tools get the repo from the token the harness signs, not from the model."""
    from audit_agent.handlers import gateway_tools
    from audit_agent.scope_token import sign
    from audit_agent.tools import REGISTRY
    from audit_agent.tools.base import ToolContext
    from audit_agent.tools.remote import remote_version
    from fix_agent.infra_graph import worker_scope

    seen = {}

    class Gateway:
        tool_names = ["read_infra_file"]

        def call(self, name, args, scope, **extra):
            seen.update(name=name, args=args, extra=extra)
            return {"data": {"ok": True}}

    tool = remote_version(REGISTRY["read_infra_file"], Gateway())
    ctx = ToolContext(scope=worker_scope(), db=db, mode="infra", extra={"infra_repo": "other-repo", "request_id": "r"})
    tool.handler(ctx, tool.parse(json.dumps({"path": "main.tf"})))
    assert seen["extra"] == {"infra_repo": "other-repo"} and "repo" not in seen["args"]

    key = b"k" * 32
    ctxobj = type("C", (), {"client_context": type("CC", (), {"custom": {"bedrockAgentCoreToolName": "gh-infra-read___read_infra_file"}})()})()
    out = gateway_tools.handler({"path": "envs/prod/main.tf", "_scope": sign(worker_scope(), key, infra_repo="other-repo")},
                                ctxobj, env=(None, key, db, InfraRepo(), (None, None)))
    assert out["data"]["repo"] == "other-repo" and out["data"]["content"] == "# prod stack\n"


def test_infra_requests_are_capped_per_person(db, drafter, monkeypatch):
    monkeypatch.setattr(api, "INFRA_DAILY_LIMIT", 3)
    deps = drafter.deps()
    for i in range(2):
        owner("insert into infra_requests (id, repo, requested_by, request, status, thread_id) "
              "values (gen_random_uuid(), %s, %s, %s, 'drafting', 'x')", (REPO, ADMIN.user_id, f"request number {i}"))
    status, out = api.infra_request(deps, ADMIN, {"request": "A third one while two run", "repo": REPO})
    assert status == 429 and "running" in out["error"]
    owner("update infra_requests set status = 'failed'")
    owner("insert into infra_requests (id, repo, requested_by, request, status, thread_id) "
          "values (gen_random_uuid(), %s, %s, 'request number 3', 'failed', 'x')", (REPO, ADMIN.user_id))
    status, out = api.infra_request(deps, ADMIN, {"request": "One more today please", "repo": REPO})
    assert status == 429 and "daily limit" in out["error"]


def test_backend_block_is_flagged():
    from fix_agent import infra_checks
    tf = 'terraform {\n  backend "s3" {\n    bucket = "x"\n  }\n}\n'
    got = {c["name"]: c for c in infra_checks.run([{"path": "b.tf", "content": tf}])}
    assert not got["No provider/backend blocks"]["ok"] and "backend s3" in got["No provider/backend blocks"]["detail"]


def test_a2a_routes_infra_actions():
    from audit_agent.scope_token import sign
    from fix_agent.a2a_server import handle

    class Infra:
        def start(self, scope, rid):
            return {"started": rid, "by": scope.user_id}

    key = b"k" * 32
    rid = "00000000-0000-0000-0000-000000000001"
    out = handle(None, key, json.dumps({"action": "infra_start", "request_id": rid, "scope_token": sign(ADMIN, key)}), Infra())
    assert out == {"started": rid, "by": ADMIN.user_id}
    assert "unknown" in handle(None, key, json.dumps({"action": "infra_start", "request_id": rid,
                                                       "scope_token": sign(ADMIN, key)}), None)["error"]
