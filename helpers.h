/* Misc helper functions. */
#ifndef HELPERS_H
#define HELPERS_H

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*(x)))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define warn(fmt, args...) \
	fprintf(stderr, "%s: " fmt "\n", argv0, ## args)
#define warnf(fmt, args...) warn("%s(): " fmt, __func__, ## args)
#define warnp(fmt, args...) warn(fmt ": %s" , ## args , strerror(errno))
#define warnfp(fmt, args...) warnf(fmt ": %s" , ## args , strerror(errno))
#define _err(wfunc, fmt, args...) \
	do { \
	wfunc("error: " fmt, ## args); \
	exit(EXIT_FAILURE); \
	} while (0)
#define err(fmt, args...) _err(warn, fmt, ## args)
#define errf(fmt, args...) _err(warnf, fmt, ## args)
#define errp(fmt, args...) _err(warnp, fmt , ## args)

static void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret)
		err("malloc(%zi) failed", size);
	return ret;
}

static char *xstrdup(const char *s)
{
	char *ret = strdup(s);
	if (!ret)
		err("strdup(%s) failed", ret);
	return ret;
}

static inline uint64_t le_buf_to_64(const char *buf)
{
	const unsigned char *ubuf = (const unsigned char *)buf;
	return
		((uint64_t)ubuf[0] << 0) +
		((uint64_t)ubuf[1] << 8) +
		((uint64_t)ubuf[2] << 16) +
		((uint64_t)ubuf[3] << 24) +
		((uint64_t)ubuf[4] << 32) +
		((uint64_t)ubuf[5] << 40) +
		((uint64_t)ubuf[6] << 48) +
		((uint64_t)ubuf[7] << 56);
}

static inline uint64_t be_buf_to_64(const char *buf)
{
	const unsigned char *ubuf = (const unsigned char *)buf;
	return
		((uint64_t)ubuf[7] << 0) +
		((uint64_t)ubuf[6] << 8) +
		((uint64_t)ubuf[5] << 16) +
		((uint64_t)ubuf[4] << 24) +
		((uint64_t)ubuf[3] << 32) +
		((uint64_t)ubuf[2] << 40) +
		((uint64_t)ubuf[1] << 48) +
		((uint64_t)ubuf[0] << 56);
}

/* This can probably be defeated, but it should be Good Enough */
static void sanitize_path(char *filename)
{
	if (filename[0] == '/') {
		warn("%s: removing leading '/' from filename", filename);
		memmove(filename, filename + 1, strlen(filename));
	}

	size_t rel_warn = 0;
	char *relpath;

	while (!strncmp(filename, "../", 3)) {
		if (!rel_warn++)
			warn("%s: removing relative paths from filename", filename);
		memmove(filename, filename + 3, strlen(filename) - 2);
	}

	while ((relpath = strstr(filename, "/../"))) {
		if (!rel_warn++)
			warn("%s: removing relative paths from filename", filename);
		memmove(relpath, relpath + 3, strlen(relpath) - 2);
	}
}

static int mktree(const char *filename)
{
	char *dupped_filename = xstrdup(filename);
	char *dir = xstrdup(dirname(dupped_filename));
	struct stat st;
	int ret = 0;
	if (stat(dir, &st) == 0)
		goto done;
	ret = mktree(dir);
	if (!ret)
		if (mkdir(dir, 0755)) {
			warnp("mkdir '%s' failed", dir);
			ret = -1;
		}
 done:
	free(dir);
	free(dupped_filename);
	return ret;
}

static int fcopy(FILE *input, FILE *output, uint64_t count)
{
	char buf[8192], *b;
	size_t expected, ret;

	while (count) {
		/* read in a chunk */
		expected = MIN(sizeof(buf), count);
		ret = fread(buf, 1, expected, input);
		if (!ret && feof(input))
			return -1;

		/* claim we've processed said chunk */
		count -= ret;

		/* now write out that chunk */
		b = buf;
		expected = ret;
		while (expected) {
			ret = fwrite(b, 1, expected, output);
			if (!ret && feof(input))
				return -1;
			expected -= ret;
			b += ret;
		}
	}

	return 0;
}

static inline void str_md5_r(const unsigned char *md5, char *output)
{
	size_t i;
	for (i = 0; i < 16; ++i)
		sprintf(output + i * 2, "%02x", md5[i]);
}
static inline char *str_md5(const unsigned char *md5)
{
	static char ret[33];
	str_md5_r(md5, ret);
	return ret;
}

#endif
