#!/bin/sh
# OpenShift's restricted-v2 SCC runs containers as a random UID in group 0
# with no /etc/passwd entry. ssh — used by publication pushes via
# GIT_SSH_COMMAND (publication/git_service.py) — hard-fails for such a UID
# ("No user exists for uid"). Register the runtime UID before handing off:
#
#  - writable root fs (plain docker / compose): append to /etc/passwd, which
#    the production image made group-0 writable for exactly this;
#  - readOnlyRootFilesystem (the Helm chart's default): write a passwd file
#    to /tmp (an emptyDir there) and point glibc at it via nss_wrapper.
#
# Git author identity needs no passwd entry — publication.git_service sets
# user.name/user.email per-clone from PUB_COMMIT_AUTHOR_*.
set -eu

if ! whoami >/dev/null 2>&1; then
    entry="advisoryhub:x:$(id -u):0:AdvisoryHub:${HOME:-/tmp}:/usr/sbin/nologin"
    if [ -w /etc/passwd ]; then
        echo "$entry" >> /etc/passwd
    elif [ -w /tmp ]; then
        echo "$entry" > /tmp/passwd
        export NSS_WRAPPER_PASSWD=/tmp/passwd
        export NSS_WRAPPER_GROUP=/etc/group
        export LD_PRELOAD=libnss_wrapper.so
    fi
fi

# exec keeps gunicorn/celery as PID 1 so SIGTERM reaches it directly
# (gunicorn graceful shutdown, celery warm shutdown).
exec "$@"
