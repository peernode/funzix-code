/* Remember, do not use the .zix format!  It is a bogus format designed to
 * perpetuate a scam (to install their adware software).  Use ZIP or RAR.
 *
 * Author:  Mike Frysinger
 * Site:    http://funzix.sf.net/
 * License: public domain
 */

/* References:
 * http://www.kennethsorling.se/scams/zix_file_format.htm
 * http://www.kennethsorling.se/scams/zix_2_file_format.htm
 */

const char * const argv0 = "funzix";

#include "headers.h"
#include "helpers.h"

size_t verbose = 0;


/* ZIX-1.0:
 * Integer quantities are in little endian
 *
 * 3 bytes: magic string "ZIX"
 * 8 bytes: offset to manifest
 * <all the files concatenated>
 * <manifest>
 */

/**
 * fmt1_process_files - process a list of files
 */
static void fmt1_process_files(FILE *fp, be_node **files, char **parent)
{
	size_t i;
	for (i = 0; files[i]; ++i) {
		be_dict *d = files[i]->val.d;

		char *filename = NULL;
		uint64_t finish = 0, size = 0, start = 0;

		while (d->val) {
			if (!strcmp(d->key, "attribute")) {
				if (d->val->val.i)
					warn("attribute is not 0?");
			} else if (!strcmp(d->key, "finish"))
				finish = d->val->val.i;
			else if (!strcmp(d->key, "name"))
				filename = d->val->val.s;
			else if (!strcmp(d->key, "size"))
				size = d->val->val.i;
			else if (!strcmp(d->key, "start"))
				start = d->val->val.i;
			++d;
		}

		if (start + size != finish)
			warn("%s: start + size != finish!", filename);
		if (verbose)
			printf("%s%s\n", *parent, filename);

		FILE *fout = fopen(filename, "w");
		off_t off = start;
		if (fseeko(fp, off, SEEK_SET))
			warnp("%s: fseek failed", filename);
		else if (fcopy(fp, fout, size))
			warnp("%s: writing failed", filename);
		fclose(fout);
	}
}

/**
 * fmt1_process_folders - process a list of folders
 */
static void fmt1_process_folders(FILE *fp, be_node **folders, char **parent)
{
	size_t i;
	for (i = 0; folders[i]; ++i) {
		be_dict *d = folders[i]->val.d;

		char *foldername = NULL;
		be_node **files = NULL;

		while (d->val) {
			if (!strcmp(d->key, "files"))
				files = d->val->val.l;
			else if (!strcmp(d->key, "name"))
				foldername = d->val->val.s;
			++d;
		}

		if (verbose)
			printf("%s%s/\n", *parent, foldername);

		*parent = realloc(*parent, strlen(*parent) + strlen(foldername) + 2);
		strcat(*parent, foldername);
		strcat(*parent, "/");

		mkdir(foldername, 0755);
		if (files) {
			if (chdir(foldername))
				warnp("%s: unable to chdir", foldername);
			else {
				fmt1_process_files(fp, files, parent);
				chdir("..");
			}
		}
	}
}

/**
 * funzix_unarchive_fmt1 - unpack archives in the ZIX-1.0 format
 *
 * Note: we do not check the magic string "ZIX" as the detection function
 *       already checked for it.  plus this way we avoid needing to do
 *       lseek on the input file which allows us to use stdin.
 */
bool funzix_unarchive_fmt1(FILE *fp)
{
	bool ret = false;
	char buf[8192];

	if (verbose > 1)
		puts(" ... ZIX-1.0 archive");

	/* first find out where the manifest is in the file */
	if (fread(buf, 1, 8, fp) != 8)
		errp("unexpected error processing header record");

	uint64_t manifest_offset = le_buf_to_64(buf);

	if (verbose > 1)
		printf(" ... manifest at offset %llu\n", (unsigned long long)manifest_offset);

	/* now read in the manifest */
	int fd = fileno(fp);
	if (fd == -1)
		err("unable to get fd backing");
	struct stat st;
	if (fstat(fd, &st))
		err("unable to stat the fd");
	long manifest_size = st.st_size - manifest_offset;
	if (fseek(fp, -manifest_size, SEEK_END))
		err("unable to seek to manifest");

	char *manifest = xmalloc(manifest_size + 1);
	if (fread(manifest, 1, manifest_size, fp) != manifest_size)
		errp("unexpected error reading manifest");
	manifest[manifest_size] = '\0';

	if (verbose > 2)
		printf(" ... manifest is %li bytes long: %s\n", manifest_size, manifest);

	/* decode the manifest into a tree of nodes */
	be_node *b = be_decode(manifest);
	if (!b)
		err("manifest contains garbage");

	if (b->type != BE_DICT)
		goto be_done;

	/* now process the files/folders in the tree */
	char *parent = xmalloc(1);
	be_dict *d = b->val.d;
	while (d->val) {
		*parent = '\0';
		if (!strcmp(d->key, "files"))
			fmt1_process_files(fp, d->val->val.l, &parent);
		else if (!strcmp(d->key, "folders"))
			fmt1_process_folders(fp, d->val->val.l, &parent);
		++d;
	}
	free(parent);

	ret = true;
 be_done:
	be_free(b);

	free(manifest);

	return ret;
}


/* ZIX-2.0:
 * Integer quantities are in big endian
 *
 * - Header
 *    6 bytes: magic string "WINZIX"
 *    2 bytes: 0x00 0x03
 * - File Record (repeats for every file)
 *    2 bytes: 0x00 0x01
 *    8 bytes: compressed size
 *    8 bytes: uncompressed size
 *    8 bytes: filename length
 *    1 byte:  0x00
 *   16 bytes: MD5 hash
 *    <filename>
 *    <file data>
 */
#define ZIX2_FILE_RECORD_HEADER_SIZE (2 + 8 + 8 + 8 + 1 + 16)

/**
 * funzix_unarchive_fmt2 - unpack archives in the ZIX-2.0 format
 *
 * Note: we do not check the magic string "WINZIX" as the detection function
 *       already checked for it.  plus this way we avoid needing to do
 *       lseek on the input file which allows us to use stdin.
 */
bool funzix_unarchive_fmt2(FILE *fp)
{
	char buf[8192], out_buf[8192];

	if (verbose > 1)
		puts(" ... ZIX-2.0 archive");

	/* check last 2 bytes in header */
	if (fread(buf, 1, 2, fp) != 2)
		errp("unexpected error processing header record");
	if (buf[0] != 0x00 || buf[1] != 0x03)
		err("header record wanted 0x00 0x03 but got 0x%02X 0x%02X", buf[0], buf[1]);

	/* process each file record */
	while (1) {
		/* first the file record header */
		size_t ret = fread(buf, 1, ZIX2_FILE_RECORD_HEADER_SIZE, fp);
		if (ret == 0 && feof(fp))
			break;
		else if (ret != ZIX2_FILE_RECORD_HEADER_SIZE)
			errp("unexpected error processing file record");

		if (buf[0] != 0x00 || buf[1] != 0x01)
			err("file record header wanted 0x00 0x01 but got 0x%02X 0x%02X", buf[0], buf[1]);

		uint64_t compressed_size = be_buf_to_64(buf + 2);
		uint64_t uncompressed_size = be_buf_to_64(buf + 2 + 8);
		uint64_t filename_len64 = be_buf_to_64(buf + 2 + 8 + 8);
		uint32_t filename_len = filename_len64;

		if (filename_len64 != filename_len)
			err("filename is too long (%llu bytes)", (unsigned long long)filename_len64);

		unsigned char md5[16];
		memcpy(md5, buf + 2 + 8 + 8 + 8 + 1, 16);

		char *filename = xmalloc(filename_len + 1);
		if (fread(filename, 1, filename_len, fp) != filename_len)
			err("unable to read filename");
		filename[filename_len] = '\0';

		if (verbose > 1) {
			printf(" ... %s: compressed: %llu bytes uncompressed: %llu bytes",
				filename,
				(unsigned long long)compressed_size,
				(unsigned long long)uncompressed_size);

			printf(" MD5: %s\n", str_md5(md5));
		} else if (verbose)
			puts(filename);

		sanitize_path(filename);

		if (mktree(filename))
			err("unable to create directories for '%s'", filename);

		/* then the actual file */
		FILE *output = fopen(filename, "w");
		if (!output)
			errp("unable to open '%s' for writing", filename);

		z_stream s = {
			.zalloc = Z_NULL,
			.zfree = Z_NULL,
			.opaque = Z_NULL,
		};
		if (inflateInit(&s) != Z_OK)
			err("zlib inflateInit() failed: %s", s.msg);

		MD5_CTX ctx;
		MD5_Init(&ctx);

		while (compressed_size) {
			s.next_in = (Bytef *)buf;
			s.avail_in = MIN(ARRAY_SIZE(buf), compressed_size);
			compressed_size -= s.avail_in;

			if (fread(buf, 1, s.avail_in, fp) != s.avail_in)
				err("failed reading compressed file");

			while (1) {
				s.next_out = (Bytef *)out_buf;
				s.avail_out = ARRAY_SIZE(out_buf);

				int zret = inflate(&s, Z_SYNC_FLUSH);
				if (zret == Z_OK || zret == Z_STREAM_END) {
					size_t len = ARRAY_SIZE(out_buf) - s.avail_out;
					MD5_Update(&ctx, out_buf, len);
					fwrite(out_buf, 1, len, output);
					if (zret == Z_STREAM_END)
						break;
				} else
					err("zlib inflate() failed: %s", s.msg);
			}
		}

		unsigned char computed_md5[16];
		MD5_Final(computed_md5, &ctx);

		if (inflateEnd(&s) != Z_OK)
			err("zlib inflateEnd() failed: %s", s.msg);

		fclose(output);

		if (memcmp(md5, computed_md5, 16)) {
			str_md5_r(md5, buf);
			str_md5_r(computed_md5, buf + 40);
			err("%s: md5 recorded as %s but output is %s", filename, buf, buf + 40);
		}

		free(filename);
	}

	return true;
}


/**
 * funzix_detect_format - detect the version of the ZIX format in use
 */
int funzix_detect_format(FILE *fp)
{
	char buf[6];

	if (fread(buf, 1, 3, fp) != 3)
		return -1;

	if (!memcmp(buf, "ZIX", 3))
		return 1;

	if (fread(buf + 3, 1, 3, fp) != 3)
		return -1;

	if (!memcmp(buf, "WINZIX", 6))
		return 2;

	return -1;
}


#define PARSE_FLAGS "C:vVh"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"directory",  a_argument, NULL, 'C'},
	{"verbose",   no_argument, NULL, 'v'},
	{"version",   no_argument, NULL, 'V'},
	{"help",      no_argument, NULL, 'h'},
};
static const char *opts_help[] = {
	"Change to specified directory",
	"Verbose mode",
	"Output program version",
	"Show help output"
};

void usage(int exit_status)
{
	size_t i;

	printf(
		"\tF the ZIX format\n"
		"\n"
		"Usage: funzix [options] <archives to unpack>\n"
		"\n"
		"Options: -[%s]\n",
		PARSE_FLAGS
	);

	for (i = 0; i < ARRAY_SIZE(long_opts); ++i)
		printf("  -%c, --%-10s %s\n",
			long_opts[i].val, long_opts[i].name,
			opts_help[i]);

	puts(
		"\n"
		"Please stop using the ZIX format.  It exists to perpetuate scumware.\n"
		"Use a real archive format like ZIP or RAR."
	);

	exit(exit_status);
}

void show_version(void)
{
	puts("F the ZIX format: version live");
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	const char *change_dir = NULL;
	char *old_dir = NULL;
	int i;

	while ((i = getopt_long(argc, argv, PARSE_FLAGS, long_opts, NULL)) != -1) {
		switch (i) {
			case 'C': change_dir = optarg; break;
			case 'v': ++verbose; break;
			case 'V': show_version();
			case 'h': usage(EXIT_SUCCESS);
			default:  usage(EXIT_FAILURE);
		}
	}
	if (optind == argc) {
		/* read from stdin if no files provided */
		optind = 0;
		argc = 1;
		argv[0] = "-";
	}

	if (change_dir) {
		size_t len = 1024;
		while (1) {
			old_dir = realloc(old_dir, len);
			if (getcwd(old_dir, len))
				break;
		}
	}

	bool ret = true;
	for (i = optind; i < argc; ++i) {
		const char *filename = argv[i];
		FILE *fp;

		if (!strcmp(filename, "-")) {
			/* special meaning: - means stdin */
			fp = stdin;
			filename = "stdin";
		} else {
			fp = fopen(filename, "rb");	/* b - "binary" for pos windows */
			if (!fp) {
				ret &= false;
				warnp("%s: cannot open", filename);
				continue;
			}
		}

		if (verbose > 1)
			printf("Unpacking archive '%s'\n", filename);

		if (change_dir) {
			if (verbose > 1)
				printf("Changing into '%s'\n", change_dir);
			if (chdir(change_dir))
				errp("%s: chdir failed", change_dir);
		}

		switch (funzix_detect_format(fp)) {
			case 1:  ret &= funzix_unarchive_fmt1(fp); break;
			case 2:  ret &= funzix_unarchive_fmt2(fp); break;
			default: ret &= false; warn("%s: file does not appear to be a ZIX archive", filename); break;
		}

		if (change_dir)
			if (chdir(old_dir))
				errp("%s: chdir back failed", old_dir);

		if (fp != stdin)
			fclose(fp);
	}

	return (ret == true ? EXIT_SUCCESS : EXIT_FAILURE);
}
