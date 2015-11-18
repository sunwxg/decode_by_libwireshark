#define HAVE_STDARG_H 1
#define WS_MSVC_NORETURN
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <wireshark/epan/epan.h>
#include <wireshark/epan/print.h>
#include <wireshark/epan/timestamp.h>
#include <wireshark/epan/prefs.h>
#include <wireshark/epan/column.h>
#include <wireshark/epan/epan-int.h>
#include <wireshark/wsutil/privileges.h>
#include <wireshark/epan/epan_dissect.h>
#include <wireshark/epan/proto.h>
#include <wireshark/epan/ftypes/ftypes.h>
#include <wireshark/epan/asm_utils.h>

extern tvbuff_t *frame_tvbuff_new(const frame_data *fd, const guint8 *buf);
static void timestamp_set(capture_file cfile);
static const nstime_t *tshark_get_frame_ts(void *data, guint32 frame_num);
static void clean();

typedef enum {
	PRINT_XML,
	PRINT_TEXT,
}print_type_t;

//global variable
capture_file cfile;

e_prefs *get_prefs()
{
	e_prefs     *prefs_p;
	char        *gpf_path, *pf_path;
	int          gpf_read_errno, gpf_open_errno;
	int          pf_open_errno, pf_read_errno;

	prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
			&pf_open_errno, &pf_read_errno, &pf_path);
	return prefs_p;
}

int init(char *filename)
{
	int          err = 0;
	gchar       *err_info = NULL;
	e_prefs     *prefs_p;

	init_process_policies();

	epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);

	cap_file_init(&cfile);
	cfile.filename = filename;

	cfile.wth = wtap_open_offline(cfile.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
	if (cfile.wth == NULL)
		goto fail;

	cfile.count = 0;
	cfile.epan = epan_new();
	cfile.epan->data = &cfile;
	cfile.epan->get_frame_ts = tshark_get_frame_ts;

	timestamp_set(cfile);
	cfile.frames = new_frame_data_sequence();

	prefs_p = get_prefs();

	build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

	return 0;

fail:
	clean();
	return err;
}

gboolean read_packet(epan_dissect_t **edt_r)
{
	epan_dissect_t    *edt;
	int                err;
	gchar             *err_info = NULL;
	static guint32     cum_bytes = 0;
	static gint64      data_offset = 0;

	struct wtap_pkthdr *whdr = wtap_phdr(cfile.wth);
	guchar             *buf = wtap_buf_ptr(cfile.wth);

	if (wtap_read(cfile.wth, &err, &err_info, &data_offset)) {

		cfile.count++;

		frame_data fdlocal;
		frame_data_init(&fdlocal, cfile.count, whdr, data_offset, cum_bytes);

		edt = epan_dissect_new(cfile.epan, TRUE, TRUE);

		frame_data_set_before_dissect(&fdlocal, &cfile.elapsed_time, &cfile.ref, cfile.prev_dis);
		cfile.ref = &fdlocal;

		epan_dissect_run(edt, cfile.cd_t, &(cfile.phdr), frame_tvbuff_new(&fdlocal, buf), &fdlocal, &cfile.cinfo);

		frame_data_set_after_dissect(&fdlocal, &cum_bytes);
		cfile.prev_cap = cfile.prev_dis = frame_data_sequence_add(cfile.frames, &fdlocal);

		//free space
		frame_data_destroy(&fdlocal);

		*edt_r = edt;
		return TRUE;
	}
	return FALSE;
}

void clean()
{
	if (cfile.frames != NULL) {
		free_frame_data_sequence(cfile.frames);
		cfile.frames = NULL;
	}

	if (cfile.wth != NULL) {
		wtap_close(cfile.wth);
		cfile.wth = NULL;
	}

	if (cfile.epan != NULL)
		epan_free(cfile.epan);

	epan_cleanup();
}

void print_each_packet_xml()
{
	epan_dissect_t *edt;

	while (read_packet(&edt)) {

		proto_tree_write_pdml(edt, stdout);

		epan_dissect_free(edt);
		edt = NULL;
	}
}

void print_each_packet_text()
{
	epan_dissect_t *edt;
	print_stream_t *print_stream;
	print_args_t    print_args;

	print_stream = print_stream_text_stdio_new(stdout);

	print_args.print_hex = TRUE;
	print_args.print_dissections = print_dissections_expanded;

	while (read_packet(&edt)) {

		proto_tree_print(&print_args, edt, print_stream);

		epan_dissect_free(edt);
		edt = NULL;
	}
}

static void
timestamp_set(capture_file cfile)
{
	switch(wtap_file_tsprecision(cfile.wth)) {
		case(WTAP_FILE_TSPREC_SEC):
			timestamp_set_precision(TS_PREC_AUTO_SEC);
			break;
		case(WTAP_FILE_TSPREC_DSEC):
			timestamp_set_precision(TS_PREC_AUTO_DSEC);
			break;
		case(WTAP_FILE_TSPREC_CSEC):
			timestamp_set_precision(TS_PREC_AUTO_CSEC);
			break;
		case(WTAP_FILE_TSPREC_MSEC):
			timestamp_set_precision(TS_PREC_AUTO_MSEC);
			break;
		case(WTAP_FILE_TSPREC_USEC):
			timestamp_set_precision(TS_PREC_AUTO_USEC);
			break;
		case(WTAP_FILE_TSPREC_NSEC):
			timestamp_set_precision(TS_PREC_AUTO_NSEC);
			break;
		default:
			g_assert_not_reached();
	}
}

static const nstime_t *
tshark_get_frame_ts(void *data, guint32 frame_num)
{
  capture_file *cf = (capture_file *) data;

  if (cf->ref && cf->ref->num == frame_num)
    return &(cf->ref->abs_ts);

  if (cf->prev_dis && cf->prev_dis->num == frame_num)
    return &(cf->prev_dis->abs_ts);

  if (cf->prev_cap && cf->prev_cap->num == frame_num)
    return &(cf->prev_cap->abs_ts);

  if (cf->frames) {
     frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

void
cap_file_init(capture_file *cf)
{
	/* Initialize the capture file struct */
	memset(cf, 0, sizeof(capture_file));
	cf->snap            = WTAP_MAX_PACKET_SIZE;
}

void print_usage(char *argv[])
{
	printf("Usage: %s -f <input_file> ", argv[0]);
	printf("[-t <xml|text> (default xml)]\n");
}

int main(int argc, char* argv[])
{

	int          err;
	char        *filename = NULL;
	print_type_t print_type = PRINT_XML;
	int          opt;

	while((opt = getopt(argc, argv, "f:t:")) != -1) {
		switch(opt) {
		case 'f':
			filename = calloc(sizeof(char), strlen(optarg) + 1);
			strncpy(filename, optarg, strlen(optarg));
			break;
		case 't':
			if (strcmp(optarg, "xml") == 0) {
				print_type = PRINT_XML;
			} else if (strcmp(optarg, "text") == 0) {
				print_type = PRINT_TEXT;
			} else {
				print_type = PRINT_XML;
			}
			break;
		default:
			print_usage(argv);
			return 1;
		}
	}

	if (filename == NULL) {
		print_usage(argv);
		return 1;
	}

	err = init(filename);
	if (err) {
		return 1;
	}

	switch (print_type) {
	case PRINT_XML:
		print_each_packet_xml();
		break;
	case PRINT_TEXT:
		print_each_packet_text();
		break;
	}

	clean();
	return 0;
}
