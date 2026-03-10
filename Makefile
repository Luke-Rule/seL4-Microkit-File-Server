.PHONY: all test tests async-tests sync-tests host-tests clean

all: test

test: async-tests sync-tests host-tests

tests: test

async-tests:
	$(MAKE) -C code/asynchronous single_test
	$(MAKE) -C code/asynchronous multi_test

sync-tests:
	$(MAKE) -C code/synchronous single_test
	$(MAKE) -C code/synchronous multi_test

host-tests:
	$(MAKE) -C code/shared_fs/fs_unit_tests clean run

clean:
	$(MAKE) -C code/asynchronous clean
	$(MAKE) -C code/synchronous clean
	$(MAKE) -C code/shared_fs/fs_unit_tests clean