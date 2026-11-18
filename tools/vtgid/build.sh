#!/bin/sh
# Сборка vtgid для модуля: NDK (r28), статически, android21 — идёт и на Android 5–8 (MT6580: 8.1).
# NDK=путь/к/ndk/<версия> sh tools/vtgid/build.sh  ->  module/bin/vtgid-arm64, module/bin/vtgid-arm
set -e
cd "$(dirname "$0")"
T="${NDK:?NDK=путь к NDK}/toolchains/llvm/prebuilt"
T="$T/$(ls "$T" | head -1)/bin"
CC64="$T/aarch64-linux-android21-clang"; CC32="$T/armv7a-linux-androideabi21-clang"
[ -x "$CC64" ] || CC64="$CC64.cmd"; [ -x "$CC32" ] || CC32="$CC32.cmd"
"$CC64" -O2 -s -static -Wall -o ../../module/bin/vtgid-arm64 vtgid.c
"$CC32" -O2 -s -static -Wall -o ../../module/bin/vtgid-arm vtgid.c
ls -l ../../module/bin/vtgid-arm64 ../../module/bin/vtgid-arm
