/*
 * Test ctime and mtime are updated on truncate(2) and ftruncate(2)
 *
 * Copyright (c) 2013 Andrew Lutomirski
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <poll.h>
#include <err.h>
#include <stdbool.h>
#include <time.h>

static int pagesize, map_len;
static int fd;
static bool ns_timestamps = true;
static int errors = 0;

static void wait_ts(void)
{
	/*
	 * Wait for the time to change.  (We need to wait long enough
	 for the FS * and for the kernel's fs timestamp granularity.)
	*/
	usleep(ns_timestamps ? 11000 : 1100000);
}

static struct timespec get_cmtime(int fd)
{
	struct stat stat;
	if (fstat(fd, &stat) < 0)
		err(1, "fstat");

	if (stat.st_mtim.tv_sec != stat.st_ctim.tv_sec ||
	    stat.st_mtim.tv_nsec != stat.st_ctim.tv_nsec) {
		printf("mtime != ctime\n");
		errors++;
	}

	printf("  [DEBUG] get_cmtime: %lld.%09ld\n",
	       (long long)stat.st_mtim.tv_sec, (long)stat.st_mtim.tv_nsec);
	wait_ts();
	return stat.st_mtim;
}

static struct timespec now()
{
	struct timespec ret;
	clock_gettime(CLOCK_REALTIME, &ret);
	printf("  [DEBUG] now:        %lld.%09ld\n",
	       (long long)ret.tv_sec, (long)ret.tv_nsec);
	wait_ts();
	return ret;
}

static bool ts_eq(const struct timespec *a, const struct timespec *b)
{
	return a->tv_sec == b->tv_sec && a->tv_nsec == b->tv_nsec;
}

static bool ts_before(const struct timespec *a, const struct timespec *b)
{
	return a->tv_sec < b->tv_sec ||
		(a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
}

#define CHECK(cond)							\
	do {								\
		if (!(cond)) {						\
			printf("*** failed check: %s\n", #cond);	\
			errors++;					\
		}							\
	} while(0)

static void *map()
{
	void *addr = mmap(0, map_len, PROT_READ | PROT_WRITE,
			  MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED)
		err(1, "mmap");
	return addr;
}

static void write_page(void *addr, int page)
{
	printf("Write page %d\n", page);
	*((char*)addr + page*pagesize) = 1;
}

static void unmap(void *addr)
{
	printf("munmap\n");
	munmap(addr, map_len);
}

static void test_basic()
{
	struct timespec t1, t2, t3;
	void *addr = map();

	printf("\ntest_basic\n");

	t1 = get_cmtime(fd);
	write_page(addr, 0);
	t2 = get_cmtime(fd);
	unmap(addr);
	t3 = get_cmtime(fd);

	CHECK(ts_before(&t1, &t3));
	CHECK(ts_eq(&t2, &t1) || ts_eq(&t2, &t3));
}

static void test_write_twice()
{
	struct timespec t1, t2, t3, t4, t5;
	void *addr = map();

	printf("\ntest_write_twice\n");

	t1 = get_cmtime(fd);
	write_page(addr, 0);
	t2 = get_cmtime(fd);
	t3 = now();
	write_page(addr, 0);
	t4 = get_cmtime(fd);
	unmap(addr);
	t5 = get_cmtime(fd);

	/* Time must change at most twice. */
	CHECK(!ts_eq(&t1, &t2) + !ts_eq(&t2, &t4) + !ts_eq(&t4, &t5) <= 2);

	/* The second write must cause an update. */
	CHECK(ts_before(&t3, &t5));
}

static void test_write_twice_sync(int sync_style)
{
	struct timespec t1, t2, t3, t4, t5, t6;
	void *addr = map();

	printf("\ntest_write_twice_sync(%d)\n", sync_style);

	t1 = get_cmtime(fd);
	write_page(addr, 0);
	t2 = get_cmtime(fd);
	t3 = now();
	write_page(addr, 0);
	t4 = get_cmtime(fd);
	if (sync_style == 0) {
		printf("fsync\n");
		fsync(fd);
	} else if (sync_style == 1) {
		printf("MS_SYNC one byte\n");
		msync(addr, 1, MS_SYNC);
	} else if (sync_style == 2) {
		printf("MS_SYNC entire mapping byte\n");
		msync(addr, map_len, MS_SYNC);
	} else if (sync_style == 3) {
		printf("MS_ASYNC one byte\n");
		msync(addr, 1, MS_ASYNC);
	} else if (sync_style == 4) {
		printf("MS_ASYNC entire mapping byte\n");
		msync(addr, map_len, MS_ASYNC);
	} else if (sync_style == 5) {
		printf("fdatasync\n");
		fdatasync(fd);
	} else if (sync_style == 6) {
		printf("sync_file_range one byte\n");
		sync_file_range(fd, 0, 1,
				SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER);
	} else {
		abort();
	}
	t5 = get_cmtime(fd);
	unmap(addr);
	t6 = get_cmtime(fd);

	/* Time must change at most twice. */
	CHECK(!ts_eq(&t1, &t2) + !ts_eq(&t2, &t4) + !ts_eq(&t4, &t5) +
	      !ts_eq(&t5, &t6) <= 2);

	/* The second write must cause an update. */
	CHECK(ts_before(&t3, &t5));

	/* Unmap must not cause an update. */
	CHECK(ts_eq(&t5, &t6));
}

static void test_two_pages()
{
	struct timespec t1, t2, t3, t4;
	void *addr = map();

	printf("\ntest_two_pages\n");

	t1 = get_cmtime(fd);
	write_page(addr, 0);
	write_page(addr, 1);
	sync_file_range(fd, 0, 1,
			SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER);
	t2 = get_cmtime(fd);
	CHECK(ts_before(&t1, &t2));

	t3 = now();
	write_page(addr, 1);
	unmap(addr);
	t4 = get_cmtime(fd);
	CHECK(ts_before(&t3, &t4));
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		return 1;
	}

	pagesize = getpagesize();

	fd = open(argv[1], O_RDWR | O_CREAT | O_EXCL, 0666);
	if (fd == -1)
		err(1, "open");

	unlink(argv[1]);

	map_len = 2*pagesize;
	if (ftruncate(fd, map_len) != 0)
		err(1, "ftruncate");

	ns_timestamps = (get_cmtime(fd).tv_nsec != 0);

	test_basic();
	test_write_twice();
	test_write_twice_sync(0);
	test_write_twice_sync(1);
	test_write_twice_sync(2);
	test_write_twice_sync(3);
	test_write_twice_sync(4);
	test_write_twice_sync(5);
	test_write_twice_sync(6);
	test_two_pages();

	if (errors) {
		printf("%d errors\n", errors);
		return 1;
	} else {
		printf("\nPassed!\n");
		return 0;
	}
}
