ASYNC_DIR := code/asynchronous
SYNC_DIR := code/synchronous
HOST_TEST_DIR := code/shared_fs/fs_unit_tests
NUM_CLIENTS ?= 3

.PHONY: all test tests async-tests sync-tests host-tests async-benchmark sync-benchmark benchmarks clean

all: test

test: async-tests sync-tests host-tests

tests: test

async-tests:
	$(MAKE) -C $(ASYNC_DIR) single_test multi_test

sync-tests:
	$(MAKE) -C $(SYNC_DIR) single_test multi_test

host-tests:
	$(MAKE) -C $(HOST_TEST_DIR) clean run

async-benchmark:
	$(MAKE) -C $(ASYNC_DIR) multi_benchmark NUM_CLIENTS=$(NUM_CLIENTS)

sync-benchmark:
	$(MAKE) -C $(SYNC_DIR) multi_benchmark NUM_CLIENTS=$(NUM_CLIENTS)

benchmarks: async-benchmark sync-benchmark

clean:
	$(MAKE) -C $(ASYNC_DIR) clean
	$(MAKE) -C $(SYNC_DIR) clean
	$(MAKE) -C $(HOST_TEST_DIR) clean