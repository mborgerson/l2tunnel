SHELL := /usr/bin/env bash
BUILD_DATE := $(shell TZ=UTC date)
BUILD_VERSION := $(shell \
	git rev-parse --short HEAD 2>/dev/null | tr -d '\n'; \
	if ! git diff --quiet HEAD &>/dev/null; then echo "-dirty"; fi; \
	)

# Common CFLAGS
CFLAGS = -Wall -Werror -pedantic -O3 \
	-DBUILD_DATE='"$(BUILD_DATE)"' \
	-DBUILD_VERSION='"$(BUILD_VERSION)"'

all: l2tunnel

# macOS/Linux
l2tunnel: l2tunnel.c
	$(CC) -o $@ $(CFLAGS) $^ -lpcap

# Windows
l2tunnel.exe: l2tunnel.c
	x86_64-w64-mingw32-gcc -o $@ $(CFLAGS) -I npcap/Include/ \
	        -L npcap/Lib/x64 $^ -l wpcap -lws2_32
l2tunnel.exe.zip: l2tunnel.exe COPYING README.md
	zip $@ $^

.PHONY:clean
clean:
	rm -f l2tunnel l2tunnel.exe l2tunnel.exe.zip
