// https://github.com/util-linux/util-linux

#include "common.h"
#include <stdint.h>
#include <stat.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <winsock.h>
#include <assert.h>

#define NDB_MSR_BASE				0xE5880000
#define NDB_MSR_PRINTK_BUF_BASE		(NDB_MSR_BASE)
#define NDB_MSR_PRINTK_BUF_LENGTH	(NDB_MSR_BASE+8)
#define NDB_MSR_MMAP				(NDB_MSR_BASE+16)
#define NDB_MSR_SYS_PARA			(NDB_MSR_BASE+24)

// Close the log.  Currently a NOP.
#define SYSLOG_ACTION_CLOSE			0
// Open the log. Currently a NOP.
#define SYSLOG_ACTION_OPEN			1
// Read from the log.
#define SYSLOG_ACTION_READ			2
// Read all messages remaining in the ring buffer. (allowed for non-root)
#define SYSLOG_ACTION_READ_ALL		3
// Read and clear all messages remaining in the ring buffer
#define SYSLOG_ACTION_READ_CLEAR	4
// Clear ring buffer.
#define SYSLOG_ACTION_CLEAR			5
// Disable printk's to console
#define SYSLOG_ACTION_CONSOLE_OFF	6
// Enable printk's to console
#define SYSLOG_ACTION_CONSOLE_ON	7
// Set level of messages printed to console
#define SYSLOG_ACTION_CONSOLE_LEVEL	8
// Return number of unread characters in the log buffer
#define SYSLOG_ACTION_SIZE_UNREAD	9
// Return size of the log buffer
#define SYSLOG_ACTION_SIZE_BUFFER	10

# define _(Text)	(Text)
# define N_(Text)	(Text)
# define NBBY		CHAR_BIT
# define __must_be_array(a)	0
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
# define isset(a,i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define is_facpri_valid(_r)	\
	    (((_r)->level > -1) && ((_r)->level < (int) ARRAY_SIZE(level_names)) && \
	     ((_r)->facility > -1) && \
	     ((_r)->facility < (int) ARRAY_SIZE(facility_names)))

enum {
	DMESG_METHOD_KMSG,		// read messages from /dev/kmsg (default)
	DMESG_METHOD_SYSLOG,	// klogctl() buffer
	DMESG_METHOD_MMAP		// mmap file with records (see --file)
};

enum {
	DMESG_TIMEFTM_NONE = 0,
	DMESG_TIMEFTM_CTIME,		// [ctime]
	DMESG_TIMEFTM_CTIME_DELTA,	// [ctime <delta>]
	DMESG_TIMEFTM_DELTA,		// [<delta>]
	DMESG_TIMEFTM_RELTIME,		// [relative]
	DMESG_TIMEFTM_TIME,			// [time]
	DMESG_TIMEFTM_TIME_DELTA,	// [time <delta>]
	DMESG_TIMEFTM_ISO8601		// 2013-06-13T22:11:00,123456+0100
};

enum {
	ISO_DATE = (1 << 0),
	ISO_TIME = (1 << 1),
	ISO_TIMEZONE = (1 << 2),
	ISO_DOTUSEC = (1 << 3),
	ISO_COMMAUSEC = (1 << 4),
	ISO_T = (1 << 5),
	ISO_GMTIME = (1 << 6),
	ISO_TIMESTAMP = ISO_DATE | ISO_TIME | ISO_TIMEZONE,
	ISO_TIMESTAMP_T = ISO_TIMESTAMP | ISO_T,
	ISO_TIMESTAMP_DOT = ISO_TIMESTAMP | ISO_DOTUSEC,
	ISO_TIMESTAMP_DOT_T = ISO_TIMESTAMP_DOT | ISO_T,
	ISO_TIMESTAMP_COMMA = ISO_TIMESTAMP | ISO_COMMAUSEC,
	ISO_TIMESTAMP_COMMA_T = ISO_TIMESTAMP_COMMA | ISO_T,
	ISO_TIMESTAMP_COMMA_G = ISO_TIMESTAMP_COMMA | ISO_GMTIME,
	ISO_TIMESTAMP_COMMA_GT = ISO_TIMESTAMP_COMMA_G | ISO_T
};

struct dmesg_name {
	const char* name;
	const char* help;
};

static const struct dmesg_name level_names[] =
{
	{"emerg", "system is unusable"},
	{ "alert", "action must be taken immediately" },
	{ "crit",  "critical conditions" },
	{"err",   "error conditions"},
	{"warn",  "warning conditions"},
	{"notice","normal but significant condition"},
	{"info",  "informational"},
	{"debug", "debug-level messages"}
};

static const struct dmesg_name facility_names[] =
{
	{"kern",     N_("kernel messages")},
	{"user",     N_("random user-level messages")},
	{"mail",     N_("mail system")},
	{"daemon",   N_("system daemons")},
	{"auth",     N_("security/authorization messages")},
	{"syslog",   N_("messages generated internally by syslogd")},
	{"lpr",      N_("line printer subsystem")},
	{"news",     N_("network news subsystem")},
	{"uucp",     N_("UUCP subsystem")},
	{"cron",     N_("clock daemon")},
	{"authpriv", N_("security/authorization messages (private)")},
	{"ftp",      N_("FTP daemon")},
};

struct dmesg_record {
	const char* mesg;
	size_t mesg_size;
	int text_length;	// added by yuqing
	int level;
	int facility;
	struct timeval tv;

	const char* next;	// buffer with next unparsed record
	size_t next_size;	// size of the next buffer
};

struct printk_log {
	uint64_t ts_nsec;	// timestamp in nanoseconds
	uint16_t len;		// length of entire record
	uint16_t text_len;	// length of text buffer
	uint16_t dict_len;	// length of dictionary buffer
	uint8_t facility;	// syslog facility
	uint8_t flags : 5;	// internal record flags
	uint8_t level : 3;	// syslog level
};

struct ul_jsonwrt {
	FILE* out;
	int indent;

	unsigned int after_close : 1;
};

typedef struct ndx_dmesg_control {
	// bit arrays -- see include/bitops.h
	char levels[ARRAY_SIZE(level_names) / NBBY + 1];
	char facilities[ARRAY_SIZE(facility_names) / NBBY + 1];

	struct timeval lasttime;	// last printed timestamp
	struct tm lasttm;			// last localtime
	struct timeval boot_time;	// system boot time
	time_t suspended_time;		// time spent in suspended state

	int action;					// SYSLOG_ACTION_*
	int	method;					// DMESG_METHOD_*

	size_t bufsize;				// size of syslog buffer

	int kmsg;					// /dev/kmsg file descriptor
	size_t kmsg_first_read;		// initial read() return code
	char kmsg_buf[BUFSIZ];		// buffer to read kmsg data

	time_t since;				// filter records by time
	time_t until;				// filter records by time

	/*
	 *	For the --file option we mmap whole file. The unnecessary (already
	 *	printed) pages are always unmapped. The result is that we have in
	 *	memory only the currently used page(s).
	 */
	
	char filename[MAX_PATH];
	char* mmap_buff;
	size_t pagesize;
	unsigned int time_fmt;		// time format

	struct ul_jsonwrt jfmt;		// -J formatting

	unsigned int follow : 1,	// wait for new messages
		end : 1,				// seek to the of buffer
		raw : 1,				// raw mode
		noesc : 1,				// no escape
		fltr_lev : 1,			// filter out by levels[]
		fltr_fac : 1,			// filter out by facilities[]
		decode : 1,				// use "facility: level: " prefix
		pager : 1,				// pipe output into a pager
		color : 1,				// colorize messages
		json : 1,				// JSON output
		force_prefix : 1;		// force timestamp and decode prefix on each line
	int	indent;					// due to timestamps if newline
} ndx_dmesg_control;

static int fwrite_hex(const char* buf, size_t size, FILE* out)
{
	size_t i;

	for (i = 0; i < size; i++) {
		int rc = fprintf(out, "\\x%02hhx  ", buf[i]);

		if (rc < 0)
			return rc;
	}

	return 0;
}

static void safe_fwrite(struct ndx_dmesg_control* dmctl, const char* buf, size_t size, int indent, FILE* out)
{
	size_t i;

	for (i = 0; i < size; i++) {
		const char* p = buf + i;
		int rc, hex = 0;
		size_t len = 1;

		if (!dmctl->noesc) {
			if (*p == '\0') {
				hex = 1;

				goto TAG_DO_PRINT;
			}
			{
				len = 1;

				if (!isprint((unsigned char)*p) && !isspace((unsigned char)*p)) {
					hex = 1;
				}
			}
		}

TAG_DO_PRINT:
		if (hex)
			rc = fwrite_hex(p, len, out);
		else if (*p == '\n' && *(p + 1) && indent)
		{
			rc = fwrite(p, 1, len, out) != len;
			if (fprintf(out, "%*s ", indent, "\n") != indent)
				rc |= 1;
		}
		else
			rc = fwrite(p, 1, len, out) != len;
	}

	return;
}

static void raw_print(struct ndx_dmesg_control* dmctl, const char* buf, size_t size)
{
	int lastc = '\n';

	if (!dmctl->mmap_buff) {
		safe_fwrite(dmctl, buf, size, 0, stdout);
		lastc = buf[size - 1];
	}
	else {
		while (size) {
			size_t sz = size > dmctl->pagesize ? dmctl->pagesize : size;
			char* x = dmctl->mmap_buff;

			safe_fwrite(dmctl, x, sz, 0, stdout);
			lastc = x[sz - 1];
			size -= sz;
			dmctl->mmap_buff += sz;
		}
	}

	if (lastc != '\n') {
		dprintf("\n");
	}

	return;
}

static int parse_kmsg_record(struct ndx_dmesg_control* dmctl, struct dmesg_record* rec, const char* buf, size_t sz)
{
	struct printk_log* kmsg = (struct printk_log*)buf;

	rec->facility = kmsg->facility;
	rec->level = kmsg->level;
	rec->mesg = buf + sizeof(struct printk_log);
	rec->mesg_size = kmsg->len;
	rec->text_length = kmsg->text_len;
	rec->tv.tv_usec = (long)kmsg->ts_nsec / 1000;
	*((char*)buf + sizeof(struct printk_log) + kmsg->text_len) = '\0';

	return 0;
}

static time_t record_time(struct ndx_dmesg_control* dmctl, struct dmesg_record* rec)
{
	return dmctl->boot_time.tv_sec + dmctl->suspended_time + rec->tv.tv_sec;
}

static int accept_record(struct ndx_dmesg_control* dmctl, struct dmesg_record* rec)
{
	if (dmctl->fltr_lev && (rec->facility < 0 || !isset(dmctl->levels, rec->level))) {
		return 0;
	}

	if (dmctl->fltr_fac && (rec->facility < 0 || !isset(dmctl->facilities, rec->facility))) {
		return 0;
	}

	if (dmctl->since && dmctl->since >= record_time(dmctl, rec)) {
		return 0;
	}

	if (dmctl->until && dmctl->until <= record_time(dmctl, rec)) {
		return 0;
	}

	return 1;
}

static struct tm* record_localtime(struct ndx_dmesg_control* dmctl, struct dmesg_record* rec, struct tm* tm)
{
	time_t t = record_time(dmctl, rec);

	return (struct tm*)localtime_s(tm, &t);
}

static char* record_ctime(struct ndx_dmesg_control* dmctl, struct dmesg_record* rec, char* buf, size_t bufsiz)
{
	struct tm tm;

	record_localtime(dmctl, rec, &tm);

	/* TRANSLATORS: dmesg uses strftime() fo generate date-time string
	   where %a is abbreviated name of the day, %b is abbreviated month
	   name and %e is day of the month as a decimal number. Please, set
	   proper month/day order here */
	if (strftime(buf, bufsiz, _("%a %b %e %H:%M:%S %Y"), &tm) == 0)
		*buf = '\0';

	return buf;
}

static double time_diff(struct timeval* a, struct timeval* b)
{
	return (a->tv_sec - b->tv_sec) + (a->tv_usec - b->tv_usec) / 1E6;
}

static double record_count_delta(struct ndx_dmesg_control* dmctl, struct dmesg_record* rec)
{
	double delta = 0;

	if (timerisset(&dmctl->lasttime))
		delta = time_diff(&rec->tv, &dmctl->lasttime);

	dmctl->lasttime = rec->tv;

	return delta;
}

static char* short_ctime(struct tm* tm, char* buf, size_t bufsiz)
{
	/* TRANSLATORS: dmesg uses strftime() fo generate date-time string
	   where: %b is abbreviated month and %e is day of the month as a
	   decimal number. Please, set proper month/day order here. */
	if (strftime(buf, bufsiz, _("%b%e %H:%M"), tm) == 0)
		*buf = '\0';

	return buf;
}

static int format_iso_time(struct tm* tm, time_t usec, int flags, char* buf, size_t bufsz)
{
	char* p = buf;
	int len;

	if (flags & ISO_DATE) {
		len = snprintf(p, bufsz, "%4ld-%.2d-%.2d",
			tm->tm_year + (long)1900,
			tm->tm_mon + 1, tm->tm_mday);
		if (len < 0 || (size_t)len > bufsz)
			goto err;
		bufsz -= len;
		p += len;
	}

	if ((flags & ISO_DATE) && (flags & ISO_TIME)) {
		if (bufsz < 1)
			goto err;
		*p++ = (flags & ISO_T) ? 'T' : ' ';
		bufsz--;
	}

	if (flags & ISO_TIME) {
		len = snprintf(p, bufsz, "%02d:%02d:%02d", tm->tm_hour,
			tm->tm_min, tm->tm_sec);
		if (len < 0 || (size_t)len > bufsz)
			goto err;
		bufsz -= len;
		p += len;
	}

	if (flags & ISO_DOTUSEC) {
		len = snprintf(p, bufsz, ".%06lld", (int64_t)usec);
		if (len < 0 || (size_t)len > bufsz)
			goto err;
		bufsz -= len;
		p += len;

	}
	else if (flags & ISO_COMMAUSEC) {
		len = snprintf(p, bufsz, ",%06lld", (int64_t)usec);
		if (len < 0 || (size_t)len > bufsz)
			goto err;
		bufsz -= len;
		p += len;
	}

	return 0;
err:
	printf(_("format_iso_time: buffer overflow."));//warnx
	return -1;
}

int strtimeval_iso(struct timeval* tv, int flags, char* buf, size_t bufsz)
{
	struct tm tm;
	struct tm* rc;

	if (flags & ISO_GMTIME)
		rc = (struct tm*)gmtime_s(&tm, (const time_t*)&tv->tv_sec);
	else
		rc = (struct tm*)localtime_s(&tm, (const time_t*)& tv->tv_sec);

	if (rc)
		return format_iso_time(&tm, tv->tv_usec, flags, buf, bufsz);

	dprintf("time %lld is out of range.", (int64_t)(tv->tv_sec));

	return -1;
}

static char* iso_8601_time(struct ndx_dmesg_control* dmctl, struct dmesg_record* rec,
	char* buf, size_t bufsz)
{
	struct timeval tv = { 0 };

	tv.tv_sec = (long)((time_t)dmctl->boot_time.tv_sec + dmctl->suspended_time + (time_t)rec->tv.tv_sec);
	tv.tv_usec = rec->tv.tv_usec;

	if (strtimeval_iso(&tv, ISO_TIMESTAMP_COMMA_T, buf, bufsz) != 0)
		return NULL;

	return buf;
}

char* xstrdup(const char* str)
{
	char* ret;

	assert(str);
	ret = _strdup(str);
	if (!ret)
		perror("cannot duplicate string");

	return ret;
}

static void print_record(struct ndx_dmesg_control* dmctl, struct dmesg_record* rec)
{
	char buf[128];
	char fpbuf[32] = "\0";
	char tsbuf[64] = "\0";
	size_t mesg_size = rec->mesg_size;
	int timebreak = 0;
	char* mesg_copy = NULL;
	const char* line = NULL;

	if (!accept_record(dmctl, rec)) {
		return;
	}

	if (!rec->mesg_size) {
		if (!dmctl->json)
			dprintf("\n");
		return;
	}

	/*
	 *	Compose syslog(2) compatible raw output -- used for /dev/kmsg for
	 *	backward compatibility with syslog(2) buffers only
	 */
	if (dmctl->raw) {
		dmctl->indent = snprintf(tsbuf, sizeof(tsbuf),
			"<%d>[%5ld.%06ld]  ",
			(long)rec->facility,
			// LOG_MAKEPRI(rec->facility, rec->level),
			(long)rec->tv.tv_sec,
			(long)rec->tv.tv_usec);
		goto full_output;
	}

	/* Store decode information (facility & priority level) in a buffer */
	if (!dmctl->json && dmctl->decode && is_facpri_valid(rec))
		snprintf(fpbuf, sizeof(fpbuf), "%-6s:%-6s: ",
			facility_names[rec->facility].name,
			level_names[rec->level].name);

	/* Store the timestamp in a buffer */
	switch (dmctl->time_fmt) {
		double delta;
		struct tm cur;
	case DMESG_TIMEFTM_NONE:
		dmctl->indent = 0;
		break;
	case DMESG_TIMEFTM_CTIME:
		dmctl->indent = snprintf(tsbuf, sizeof(tsbuf), "[%s] ",
			record_ctime(dmctl, rec, buf, sizeof(buf)));
		break;
	case DMESG_TIMEFTM_CTIME_DELTA:
		dmctl->indent = snprintf(tsbuf, sizeof(tsbuf), "[%s <%12.06f>] ",
			record_ctime(dmctl, rec, buf, sizeof(buf)),
			record_count_delta(dmctl, rec));
		break;
	case DMESG_TIMEFTM_DELTA:
		dmctl->indent = snprintf(tsbuf, sizeof(tsbuf), "[<%12.06f>] ",
			record_count_delta(dmctl, rec));
		break;
	case DMESG_TIMEFTM_RELTIME:
		record_localtime(dmctl, rec, &cur);
		delta = record_count_delta(dmctl, rec);
		if (cur.tm_min != dmctl->lasttm.tm_min ||
			cur.tm_hour != dmctl->lasttm.tm_hour ||
			cur.tm_yday != dmctl->lasttm.tm_yday) {
			timebreak = 1;
			dmctl->indent = snprintf(tsbuf, sizeof(tsbuf), "[%s] ",
				short_ctime(&cur, buf,
					sizeof(buf)));
		}
		else {
			if (delta < 10)
				dmctl->indent = snprintf(tsbuf, sizeof(tsbuf),
					"[%+8.06f]", delta);
			else
				dmctl->indent = snprintf(tsbuf, sizeof(tsbuf),
					"[%+9.06f]", delta);
		}
		dmctl->lasttm = cur;
		break;
	case DMESG_TIMEFTM_TIME:
		dmctl->indent = snprintf(tsbuf, sizeof(tsbuf),
			dmctl->json ? "%5ld.%06ld" : "[%5ld.%06ld]",
			(long)rec->tv.tv_sec,
			(long)rec->tv.tv_usec);
		break;
	case DMESG_TIMEFTM_TIME_DELTA:
		dmctl->indent = snprintf(tsbuf, sizeof(tsbuf), "[%5ld.%06ld <%12.06f>] ",
			(long)rec->tv.tv_sec,
			(long)rec->tv.tv_usec,
			record_count_delta(dmctl, rec));
		break;
	case DMESG_TIMEFTM_ISO8601:
		dmctl->indent = snprintf(tsbuf, sizeof(tsbuf), "%s ",
			iso_8601_time(dmctl, rec, buf,
				sizeof(buf)));
		break;
	default:
		abort();
	}

	dmctl->indent += (int)strlen(fpbuf);

full_output:
	/* Output the decode information */
	if (*fpbuf) {
		dprintf(fpbuf);
	}

	/* Output the timestamp buffer */
	if (*tsbuf) {
		/* Colorize the timestamp */
		if (dmctl->time_fmt != DMESG_TIMEFTM_RELTIME) {
			if (dmctl->json)
				dprintf("ul_jsonwrt_value_raw");
			else
				dprintf(tsbuf, stdout);
		}
		else {
			/*
			 * For relative timestamping, the first line's
			 * timestamp is the offset and all other lines will
			 * report an offset of 0.000000.
			 */
			dprintf(!line ? tsbuf : "[  +0.000000] ", stdout);
		}
		dprintf("[%s]", level_names[rec->level].name);
	}

	/*
	 * A kernel message may contain several lines of output, separated
	 * by '\n'.  If the timestamp and decode outputs are forced then each
	 * line of the message must be displayed with that information.
	 */
	if (dmctl->force_prefix) {
		if (!line) {
			mesg_copy = xstrdup(rec->mesg);
			line = strtok(mesg_copy, "\n");
			if (!line)
				goto done;	/* only when something is wrong */
		}
	}
	else {
		line = rec->mesg;
		mesg_size = rec->mesg_size;
	}

	dprintf(line);

	/* Get the next line */
	if (dmctl->force_prefix) {
		line = strtok(NULL, "\n");
		if (line && *line) {
			dprintf("\n");
			mesg_size = strlen(line);
			goto full_output;
		}
	}

done:
	free(mesg_copy);
	if (dmctl->json)
		dprintf("ul_jsonwrt_object_close\n");
	else

		dprintf("\n");
}

static void print_buffer(struct ndx_dmesg_control* dmctl, const char* buf, size_t size)
{
	size_t sz = size;
	const char* cursor = buf, * end = buf + size;
	struct dmesg_record rec = { 0 };

	rec.next = buf;
	rec.next_size = size;

	if (dmctl->raw) {
		raw_print(dmctl, buf, size);
		return;
	}
	do {
		if (parse_kmsg_record(dmctl, &rec, cursor, (size_t)sz) == 0) {
			print_record(dmctl, &rec);
		}

		cursor += rec.mesg_size;
	} while (cursor < end);

	return;
}

void dmesg_decode_file(const char* fpath)
{
	int fd;
	int rfd;
	char* p = NULL;
	struct stat sb;
	ndx_dmesg_control dmctl = { 0 };

	snprintf(dmctl.filename, MAX_PATH, "%s", fpath);
	dmctl.action = SYSLOG_ACTION_READ_ALL;
	dmctl.method = DMESG_METHOD_KMSG;
	dmctl.kmsg = -1;
	dmctl.time_fmt = DMESG_TIMEFTM_TIME;
	dmctl.indent = 0;
	dmctl.raw = 0;

	if (stat(fpath, &sb) == -1) {
		dprintf("failed to get file stat,please check!\n");

		return;
	}

	dprintf("file size : %lld bytes\n", (long long)sb.st_size);
	dprintf("%s\n", dmctl.filename);

	fd = open(fpath, O_RDONLY);
	p = (char*)malloc(sb.st_size);
	rfd = read(fd, p, sb.st_size);
	if (rfd < 0) {
		dprintf("read file fail\n");

		goto TAG_RETURN;
	}
	close(fd);

	print_buffer(&dmctl, p, sb.st_size);

TAG_RETURN:
	if (p != NULL)
	{
		free(p);
	}

	return;
}

void dmesg_decode_memory(void)
{
	ULONGLONG prtk_base, cursor, prtk_len;
	ULONG status, n_total, n_remaining, count;
	double delta;
	double msec;
	char szText[MAX_PATH * 2] = { 0 };
	char ts_buf[64] = { 0 };
	struct printk_log header;

	header = { 0 };

	ReadMsr(NDB_MSR_PRINTK_BUF_BASE, &prtk_base);
	ReadMsr(NDB_MSR_PRINTK_BUF_LENGTH, &prtk_len);
	dprintf("prink buffer base : %I64x, length : 0x%I64x\n", prtk_base, prtk_len);
	cursor = prtk_base;

	do {
		status = ReadMemory(cursor, &header, sizeof(header), &count);

		if (CheckControlC() == TRUE) {
			break;
		}

		if (status && count == sizeof(header)) {
			n_total = header.len;
			delta = (double)header.ts_nsec / 1000000000;
			msec = (double)header.ts_nsec / 1000;

			if (delta < 10)
			{
				snprintf(ts_buf, sizeof(ts_buf), "%13.7f", delta);
			}
			else
			{
				snprintf(ts_buf, sizeof(ts_buf), "%14.7f", delta);
			}

			if (header.text_len == 0) {
				// dmesg end
				break;
			}

			n_remaining = n_total - sizeof(header);	// to be aligned 
			status = ReadMemory(cursor + sizeof(header), szText, n_remaining, &count);

			if (status && count == n_remaining) {
				dprintf("[%s] %s\n", ts_buf, szText);

				cursor += n_total;
			}
		}

	} while (1);

	return;
}
