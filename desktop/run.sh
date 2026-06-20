#!/usr/bin/env bash
# Launch AetherAV desktop with a sanitized environment.
#
# Snap-packaged apps (notably the VS Code snap and its integrated terminal)
# export LD_LIBRARY_PATH / GTK_PATH pointing into /snap/core*/.../lib. Native
# binaries launched from such a shell then load the snap's libc/libpthread and
# crash with:
#     symbol lookup error: .../libpthread.so.0: undefined symbol:
#     __libc_pthread_init, version GLIBC_PRIVATE
# Clearing those variables for our process fixes it (the GUI doesn't need them).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/src-tauri/target/release/aether-desktop"
[ -x "$BIN" ] || BIN="$DIR/src-tauri/target/debug/aether-desktop"

if [ ! -x "$BIN" ]; then
  echo "binary not found - build it first:  (cd '$DIR/src-tauri' && cargo build)" >&2
  exit 1
fi

exec env -u LD_LIBRARY_PATH \
        -u GTK_PATH \
        -u GTK_EXE_PREFIX \
        -u GDK_PIXBUF_MODULE_FILE \
        -u GDK_PIXBUF_MODULEDIR \
        -u GIO_MODULE_DIR \
        -u GSETTINGS_SCHEMA_DIR \
        -u LOCPATH \
        "$BIN" "$@"
