"""Deterministic manifest edits. The version bump is plain code, not model output: it is
exact, testable, and cannot be talked into changing anything else in the file."""
from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass

NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
PIN_RE = r"^(?P<pre>\s*{name}\s*(?:\[[^\]]*\])?\s*)(?P<op>==|>=|~=|<=|<|>|!=)?\s*(?P<ver>[A-Za-z0-9_.+\-*]+)?(?P<post>[^\n#]*)(?P<comment>#.*)?$"


class ManifestError(ValueError):
    pass


@dataclass
class Edit:
    path: str
    old: str
    new: str
    old_spec: str
    new_spec: str

    @property
    def diff(self) -> str:
        return "".join(difflib.unified_diff(self.old.splitlines(keepends=True), self.new.splitlines(keepends=True),
                                            fromfile=f"a/{self.path}", tofile=f"b/{self.path}"))


def version_tuple(v: str) -> tuple:
    parts = re.findall(r"\d+|[A-Za-z]+", v)
    return tuple(int(p) if p.isdigit() else -1 for p in parts[:4]) or (0,)


def at_least(v: str, minimum: str) -> bool:
    return version_tuple(v) >= version_tuple(minimum)


NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")


def manifest_for(path: str) -> str:
    """Dependabot often reports the lockfile. The fix edits the declared range in the
    package.json beside it; CI regenerates the lockfile (the PR says so)."""
    head, _, name = path.rpartition("/")
    if name in NPM_LOCKFILES:
        return f"{head}/package.json" if head else "package.json"
    return path


def bump(path: str, content: str, package: str, target: str) -> Edit:
    name = path.rsplit("/", 1)[-1]
    if name == "package.json":
        return _bump_package_json(path, content, package, target)
    if name.endswith(".txt") and "requirements" in name:
        return _bump_requirements(path, content, package, target)
    raise ManifestError(f"Automatic fixes support package.json and requirements*.txt, not {name}.")


def _bump_package_json(path: str, content: str, package: str, target: str) -> Edit:
    try:
        doc = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{path} is not valid JSON") from exc
    for section in NPM_SECTIONS:
        spec = (doc.get(section) or {}).get(package)
        if spec is None:
            continue
        m = re.match(r"^(?P<prefix>[\^~]|>=)?\s*(?P<ver>\d[\w.+\-]*)$", str(spec).strip())
        if not m:
            raise ManifestError(f"{package} is pinned as '{spec}', which can't be bumped automatically.")
        if at_least(m.group("ver"), target):
            raise ManifestError(f"{package} is already at {spec} (fixed in {target}); the lockfile may be stale.")
        new_spec = f"{m.group('prefix') or ''}{target}"
        # Replace only that one value in the original text, keeping the file's formatting.
        pattern = re.compile(r'("' + re.escape(package) + r'"\s*:\s*")' + re.escape(str(spec)) + r'(")')
        new, n = pattern.subn(lambda mm: mm.group(1) + new_spec + mm.group(2), content, count=1)
        if n != 1:
            raise ManifestError(f"Could not locate {package} in {path} text.")
        json.loads(new)   # still valid
        return Edit(path, content, new, str(spec), new_spec)
    raise ManifestError(f"{package} is not a direct dependency in {path} (it may come from the lockfile).")


def _bump_requirements(path: str, content: str, package: str, target: str) -> Edit:
    lines = content.splitlines(keepends=True)
    norm = lambda s: re.sub(r"[-_.]+", "-", s).lower()  # noqa: E731  (PEP 503 names)
    for i, line in enumerate(lines):
        body = line.rstrip("\n")
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)", body)
        if not m or norm(m.group(1)) != norm(package):
            continue
        pm = re.match(PIN_RE.format(name=re.escape(m.group(1))), body)
        if not pm or pm.group("op") not in ("==", ">=", "~=", None):
            raise ManifestError(f"{package} has a specifier that can't be bumped automatically: {body.strip()}")
        old_ver = pm.group("ver")
        if old_ver and at_least(old_ver, target):
            raise ManifestError(f"{package} is already at {old_ver} (fixed in {target}).")
        tail = body[pm.end("ver"):] if old_ver else body[pm.end("pre"):]
        new_body = f"{pm.group('pre').rstrip()}=={target}{tail}"   # everything after the version is kept
        lines[i] = new_body + ("\n" if line.endswith("\n") else "")
        return Edit(path, content, "".join(lines), body.strip(), new_body.strip())
    raise ManifestError(f"{package} is not listed in {path}.")
