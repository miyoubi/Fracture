API ?= 30
PROJECT ?= unified
OUTDIR ?= build/$(PROJECT)

TARGET_DIR := src/targets/$(PROJECT)
ifeq ($(PROJECT),unified)
TARGET_HEADER :=
else
TARGET_HEADER := $(TARGET_DIR)/target.h
ifeq ($(wildcard $(TARGET_HEADER)),)
$(error unknown PROJECT=$(PROJECT), missing $(TARGET_HEADER))
endif
endif

TARGET := $(OUTDIR)/kgsl_root_su
LIB := $(OUTDIR)/libfracture.so
SOURCES := src/main.c src/target_profile.c \
           src/selinux_handoff.c \
           src/ko_loader.c
HEADERS := $(wildcard src/*.h $(TARGET_DIR)/*.h)
ifeq ($(PROJECT),unified)
TARGET_CFLAGS := -Isrc -DTARGET_UNIFIED=1
else
TARGET_CFLAGS := -Isrc -DTARGET_CONFIG_H=\"targets/$(PROJECT)/target.h\"
endif

NDK_HOST_TAG ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')-$(shell uname -m)
NDK_ROOT ?= $(or $(ANDROID_NDK_ROOT),$(ANDROID_NDK_HOME),$(NDK_HOME),$(NDK),\
             $(firstword $(wildcard $(HOME)/Android/Sdk/ndk/*)))
COMPILER ?= $(or $(ANDROID_CC),\
             $(if $(NDK_ROOT),$(NDK_ROOT)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)/bin/aarch64-linux-android$(API)-clang,\
             aarch64-linux-android$(API)-clang))

CFLAGS ?= -O2 -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -fPIE -pthread
LDFLAGS ?= -pie -pthread -ldl

.PHONY: all bin lib clean info list-projects

all: bin lib

bin: $(TARGET)

lib: $(LIB)

$(TARGET): $(SOURCES) $(HEADERS)
	mkdir -p $(OUTDIR)
	$(COMPILER) $(CFLAGS) $(TARGET_CFLAGS) $(SOURCES) $(LDFLAGS) -o $@

$(LIB): $(SOURCES) $(HEADERS) src/preload.c
	mkdir -p $(OUTDIR)
	$(COMPILER) -O2 -std=gnu11 -Wall -Wextra -Werror \
		-Wno-unused-parameter -Wno-unused-variable \
		-fPIC -shared -Dmain=kgsl_root_su_main \
		$(TARGET_CFLAGS) $(SOURCES) src/preload.c \
		-pthread -ldl -o $@

info:
	@echo "PROJECT=$(PROJECT)"
	@echo "TARGET=$(TARGET)"
	@echo "LIB=$(LIB)"
	@echo "COMPILER=$(COMPILER)"

list-projects:
	@echo unified
	@find src/targets -mindepth 2 -maxdepth 2 -name target.h -printf '%h\n' | sed 's#src/targets/##' | sort

clean:
	rm -rf build
