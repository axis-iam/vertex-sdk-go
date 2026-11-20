#!/usr/bin/env python3
"""Archive this candidate and test clean public-module consumers, without replace."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build" / "bff-consumers"
MODULE = "github.com/axis-iam/vertex-sdk-go"
VERSION = "v0.1.1"  # isolated candidate coordinate; no tag/publication implied
MODULES = {"http": ROOT, **{name: ROOT / name for name in ("chi", "gin", "echo")}}
ENV = dict(os.environ, GOWORK="off")
for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    ENV[key] = "http://127.0.0.1:7897"


def run(argv, cwd, env=ENV):
    print("+", " ".join(argv), f"[{Path(cwd).relative_to(ROOT)}]", flush=True)
    subprocess.run(argv, cwd=cwd, env=env, check=True)


def archive(name, directory):
    module = MODULE if name == "http" else MODULE + "/" + name
    target = OUT / "proxy" / module / "@v"
    target.mkdir(parents=True, exist_ok=True)
    files = []
    public_paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=directory,
    ).decode().split("\0")
    for relative in sorted(set(public_paths)):
        if not relative:
            continue
        file = directory / relative
        if not file.is_file():
            continue
        rel = file.relative_to(directory)
        if any(part.startswith(".") for part in rel.parts) or rel.parts[0] in (
            "build", "dist", "bin", "vendor",
        ):
            continue
        if name == "http" and rel.parts[0] in ("chi", "gin", "echo", "examples"):
            continue  # independent nested modules / separately consumed example
        if file.name in ("go.work", "go.work.sum") or file.suffix in (".log", ".out"):
            continue
        if file.is_symlink():
            raise RuntimeError(f"symlink in candidate: {rel}")
        if any(part in ("tasks", "plans", ".codex", ".git") for part in rel.parts):
            raise RuntimeError(f"internal material in candidate: {rel}")
        data = file.read_bytes()
        private_home = b"/home/" + b"chaos/"
        private_key_marker = b"BEGIN " + b"PRIVATE KEY"
        if private_home in data or private_key_marker in data:
            raise RuntimeError(f"private content in archive: {rel}")
        files.append((rel.as_posix(), data))
    if b"replace " in (directory / "go.mod").read_bytes():
        raise RuntimeError(f"published replace in {name}")
    path = target / (VERSION + ".zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for rel, data in files:
            info = zipfile.ZipInfo(f"{module}@{VERSION}/{rel}", (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    (target / (VERSION + ".mod")).write_bytes((directory / "go.mod").read_bytes())
    (target / (VERSION + ".info")).write_text(json.dumps({"Version": VERSION, "Time": "2026-11-19T00:00:00Z"}))
    (target / "list").write_text(VERSION + "\n")
    return {"module": module, "version": VERSION, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "fileCount": len(files), "path": str(path.relative_to(ROOT)),
            "sourceDigest": hashlib.sha256(b"".join(rel.encode() + b"\0" + data for rel, data in files)).hexdigest()}


MOUNTS = {
    "http": """
func mount(s *websession.Service, business http.Handler) http.Handler {
    r:=http.NewServeMux()
    r.Handle("/auth/",s.Handler())
    r.Handle("/business",s.Middleware(business))
    r.Handle("/denied",s.Middleware(business))
    r.Handle("/business-write",s.Middleware(business))
    return r
}
""",
    "chi": """
func mount(s *websession.Service, business http.Handler) http.Handler {
    r:=chi.NewRouter()
    r.Mount("/auth",adapter.WebSessionHandler(s))
    r.With(adapter.WebSession(s)).Handle("/business",business)
    r.With(adapter.WebSession(s)).Handle("/denied",business)
    r.With(adapter.WebSession(s)).Handle("/business-write",business)
    return r
}
""",
    "gin": """
func mount(s *websession.Service, business http.Handler) http.Handler {
    gin.SetMode(gin.TestMode)
    r:=gin.New()
    r.Any("/auth/*path",adapter.WebSessionHandler(s))
    r.GET("/business",adapter.WebSession(s),gin.WrapH(business))
    r.GET("/denied",adapter.WebSession(s),gin.WrapH(business))
    r.Any("/business-write",adapter.WebSession(s),gin.WrapH(business))
    return r
}
""",
    "echo": """
func mount(s *websession.Service, business http.Handler) http.Handler {
    r:=echo.New()
    r.Any("/auth/*",adapter.WebSessionHandler(s))
    r.GET("/business",echo.WrapHandler(business),adapter.WebSession(s))
    r.GET("/denied",echo.WrapHandler(business),adapter.WebSession(s))
    r.Any("/business-write",echo.WrapHandler(business),adapter.WebSession(s))
    return r
}
""",
}
IMPORTS = {
    "http": "",
    "chi": '"github.com/go-chi/chi/v5"\nadapter "' + MODULE + '/chi"',
    "gin": '"github.com/gin-gonic/gin"\nadapter "' + MODULE + '/gin"',
    "echo": '"github.com/labstack/echo/v4"\nadapter "' + MODULE + '/echo"',
}


def main():
    business_csrf = "--business-csrf" in sys.argv[1:]
    OUT.mkdir(parents=True, exist_ok=True)
    old_cache = subprocess.check_output(["go", "env", "GOMODCACHE"], cwd=ROOT, env=ENV, text=True).strip()
    # Separate cache prevents an old cached public v0.1.1 from shadowing candidate
    # archives. Dependency cache is a read-only fallback, then the normal registry.
    env = dict(ENV, GOMODCACHE=str(OUT / "module-cache"),
               GOPROXY=f"file://{OUT / 'proxy'},file://{old_cache}/cache/download,https://proxy.golang.org",
               GONOSUMDB=MODULE + "*")
    if (OUT / "module-cache").exists():
        subprocess.run(["chmod", "-R", "u+w", str(OUT / "module-cache")], check=True)
        shutil.rmtree(OUT / "module-cache")
    receipts = [archive(name, directory) for name, directory in MODULES.items()]
    if not business_csrf:
        run(["go", "test", ".", "-run", "^(TestSDK_Authenticate|TestSDK_RequirePerm|TestCurrentUserNullableAndStrictContext|TestConfig_NoAudienceInference)$", "-count=1"], ROOT)
        run(["go", "test", "./middleware", "-run", "^(TestAuth_Valid|TestAuthDependencyFailures|TestRequirePerm)$", "-count=1"], ROOT)
    else:
        run(["go", "test", "./websession", "-run", "^TestWebSessionBusinessCSRFGuardCachedIdentity$", "-count=1"], ROOT)
    for name, directory in MODULES.items():
        if name != "http" and not business_csrf:
            source_env = dict(ENV, GOWORK=str(ROOT / "go.work"))
            run(["go", "test", ".", "-run", "^(TestResourceAudienceContract|TestAuthDependencyFailures)$", "-count=1"], directory, source_env)
        consumer = OUT / ("consumer-" + name)
        consumer.mkdir(exist_ok=True)
        for file in ("go.mod", "go.sum"):
            (consumer / file).unlink(missing_ok=True)
        required = f"\t{MODULE} {VERSION}\n"
        if name != "http":
            required += f"\t{MODULE}/{name} {VERSION}\n"
        (consumer / "go.mod").write_text(f"module consumer.example/{name}\n\ngo 1.23\n\nrequire (\n{required})\n")
        shutil.copyfile(ROOT / "scripts/bff-consumer/consumer_test.go.txt", consumer / "consumer_test.go")
        (consumer / "mount_test.go").write_text('package consumer\nimport (\n"net/http"\n"' + MODULE +
                                               '/websession"\n' + IMPORTS[name] + "\n)\n" + MOUNTS[name])
        run(["go", "mod", "tidy"], consumer, env)
        run(["go", "test", ".", "-run", "^TestBFFConsumer$", "-count=1"], consumer, env)
        run(["go", "vet", "."], consumer, env)
        if "replace " in (consumer / "go.mod").read_text():
            raise RuntimeError("consumer replace detected")
        resolved = json.loads(subprocess.check_output(["go", "list", "-m", "-json", MODULE], cwd=consumer, env=env, text=True))
        if not str(resolved["Dir"]).startswith(str(OUT / "module-cache")):
            raise RuntimeError("candidate did not resolve from isolated module cache")
    if not business_csrf:
        run(["go", "vet", "./websession"], ROOT)
    example = OUT / "example-server"
    if example.exists():
        shutil.rmtree(example)
    shutil.copytree(ROOT / "examples/bff-server", example)
    run(["go", "mod", "tidy"], example, env)
    run(["go", "build", "-o", str(OUT / "bff-example"), "."], example, env)
    if "replace " in (example / "go.mod").read_text():
        raise RuntimeError("example replace detected")
    manifest = {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "dirtySource": True, "archivePolicy": "normalized ZIP; isolated candidate v0.1.1, not a public release",
                "modules": receipts, "consumers": list(MODULES),
                "exampleBinarySha256": hashlib.sha256((OUT / "bff-example").read_bytes()).hexdigest(),
                "browserProof": "PENDING actual JS tarballs and controlled IAM WEB fixture", "result": "PASS"}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest), flush=True)


if __name__ == "__main__":
    main()
