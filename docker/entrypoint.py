"""Container entrypoint: register the runtime UID, then exec the command.

OpenShift's restricted-v2 SCC runs containers as a random UID in group 0
with no /etc/passwd entry. ssh — used by publication pushes via
GIT_SSH_COMMAND (publication/git_service.py) — hard-fails for such a UID
("No user exists for uid"). Register the runtime UID before handing off
by pointing glibc at a passwd copy under /tmp via nss_wrapper; /tmp is
always writable (an emptyDir under the Helm chart's default
readOnlyRootFilesystem), so one code path covers writable and read-only
root filesystems alike.

The exec'd process inherits the mutated environment, and the publication
git layer extends os.environ per call, so LD_PRELOAD/NSS_WRAPPER_* reach
the git -> ssh children.

Python stdlib only — the production image ships no shell.
"""

import glob
import os
import pwd
import sys


def main() -> None:
    if len(sys.argv) < 2:
        print("entrypoint: no command given", file=sys.stderr)
        raise SystemExit(2)

    try:
        pwd.getpwuid(os.getuid())
    except KeyError:
        _register_uid()

    # exec keeps gunicorn/celery as PID 1 so SIGTERM reaches it directly
    # (gunicorn graceful shutdown, celery warm shutdown).
    os.execvp(sys.argv[1], sys.argv[1:])


def _register_uid() -> None:
    """Make the runtime UID resolvable through nss_wrapper.

    nss_wrapper *replaces* the passwd database rather than augmenting it,
    so the system entries are copied over first (root and the base
    image's users must stay resolvable). Failure is a warning rather than
    an abort: everything except ssh works fine without a passwd entry.
    """
    # No ldconfig ever runs in the final image, so /etc/ld.so.cache never
    # lists the staged lib — resolve an absolute path instead of trusting
    # soname lookup.
    libs = sorted(glob.glob("/usr/lib/*/libnss_wrapper.so*"))
    if not libs:
        print(
            "entrypoint: libnss_wrapper.so not found (ssh will fail for this UID)",
            file=sys.stderr,
        )
        return

    home = os.environ.get("HOME", "/tmp")
    entry = f"advisoryhub:x:{os.getuid()}:0:AdvisoryHub:{home}:/usr/sbin/nologin\n"
    try:
        with open("/etc/passwd", encoding="utf-8") as f:
            base = f.read()
        if base and not base.endswith("\n"):
            base += "\n"
    except OSError:
        base = ""
    try:
        with open("/tmp/passwd", "w", encoding="utf-8") as f:
            f.write(base + entry)
    except OSError as exc:
        print(
            f"entrypoint: cannot write /tmp/passwd (ssh will fail for this UID): {exc}",
            file=sys.stderr,
        )
        return

    os.environ["NSS_WRAPPER_PASSWD"] = "/tmp/passwd"
    os.environ["NSS_WRAPPER_GROUP"] = "/etc/group"
    os.environ["LD_PRELOAD"] = libs[0]


if __name__ == "__main__":
    main()
