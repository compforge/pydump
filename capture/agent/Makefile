PYTHON ?= python3
CC ?= cc
BUILD_DIR ?= build
PYTHON_MINOR := $(shell $(PYTHON) -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
MACHINE := $(shell uname -m)
TARGET := $(BUILD_DIR)/pydump-agent-$(PYTHON_MINOR)-$(MACHINE).so
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -fPIC -fvisibility=hidden -Wall -Wextra -Werror -Wpedantic
CPPFLAGS += -DPy_BUILD_CORE $(shell $(PYTHON)-config --includes)
ifeq ($(shell uname -s),Darwin)
LDFLAGS += -bundle -undefined dynamic_lookup -pthread
else
LDFLAGS += -shared -pthread
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): agent.c object_facts.c object_facts.h protocol.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) agent.c object_facts.c $(LDFLAGS) -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -f $(BUILD_DIR)/pydump-agent-*.so
