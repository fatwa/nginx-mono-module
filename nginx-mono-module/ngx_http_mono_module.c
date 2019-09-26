/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_rwlock.h>

#include <mono/jit/jit.h>
#include <mono/metadata/assembly.h>
#include <mono/metadata/object.h>
#include <mono/metadata/mono-config.h>
#include <mono/metadata/appdomain.h>
#include <mono/metadata/threads.h>

#ifdef _MSC_VER
#ifndef NDEBUG
#define CONSOLE 1
#endif // NDEBUG
#pragma comment(lib, "mono-2.0-sgen.lib")
#endif // _MSC_VER

#ifdef _WIN32
#define OS_PATH_CHAR	'\\'
#define OS_PATH_STRING	"\\"
#else
#define OS_PATH_CHAR	'/'
#define OS_PATH_STRING	"/"
#endif // _WIN32

#define MAX_STATUS_LENGTH	192
static const u_char DEFAULT_CONTENT_TYPE[] = "text/html; charset=utf-8";
static const u_char DEFAULT_CONTENT_CHARSET[] = "utf-8";
static const char ERROR_HTML[] = "<html><head><title>%s</title></head><body><h1>%s %d</h1>%s</body></html>";
static const char *status_code_string(int32_t code)
{
	switch (code)
	{
	case NGX_HTTP_CONTINUE: return "Continue";
	case NGX_HTTP_SWITCHING_PROTOCOLS: return "Switching Protocols";
	case NGX_HTTP_PROCESSING: return "Processing";

	case NGX_HTTP_OK: return "OK";
	case NGX_HTTP_CREATED: return "Created";
	case NGX_HTTP_ACCEPTED: return "Accepted";
	case 203: return "Non-Authoritative Information";
	case NGX_HTTP_NO_CONTENT: return "No Content";
	case 205: return "Reset Content";
	case NGX_HTTP_PARTIAL_CONTENT: return "Partial Content";
	case 207: return "Multi-Status";

	case NGX_HTTP_SPECIAL_RESPONSE: return "Multiple Choices";
	case NGX_HTTP_MOVED_PERMANENTLY: return "Moved Permanently";
	case NGX_HTTP_MOVED_TEMPORARILY: return "Found";
	case NGX_HTTP_SEE_OTHER: return "See Other";
	case NGX_HTTP_NOT_MODIFIED: return "Not Modified";
	case 305: return "Use Proxy";
	case 306: return "Switch Proxy";
	case NGX_HTTP_TEMPORARY_REDIRECT: return "Temporary Redirect";

	case NGX_HTTP_BAD_REQUEST: return "Bad Request";
	case NGX_HTTP_UNAUTHORIZED: return "Unauthorized";
	case 402: return "Payment Required";
	case NGX_HTTP_FORBIDDEN: return "Forbidden";
	case NGX_HTTP_NOT_FOUND: return "Not Found";
	case NGX_HTTP_NOT_ALLOWED: return "Method Not Allowed";
	case 406: return "Not Acceptable";
	case 407: return "Proxy Authentication Required";
	case NGX_HTTP_REQUEST_TIME_OUT: return "Request Timeout";
	case NGX_HTTP_CONFLICT: return "Conflict";
	case 410: return "Gone";
	case NGX_HTTP_LENGTH_REQUIRED: return "Length Required";
	case NGX_HTTP_PRECONDITION_FAILED: return "Precondition Failed";
	case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE: return "Request Entity Too Large";
	case NGX_HTTP_REQUEST_URI_TOO_LARGE: return "Request-Uri Too Long";
	case NGX_HTTP_UNSUPPORTED_MEDIA_TYPE: return "Unsupported Media Type";
	case NGX_HTTP_RANGE_NOT_SATISFIABLE: return "Requested Range Not Satisfiable";
	case 417: return "Expectation Failed";
	case 422: return "Unprocessable Entity";
	case 423: return "Locked";
	case 424: return "Failed Dependency";
	case 425: return "Unordered Collection";
	case 426: return "Upgrade Required";
	case 449: return "Retry With";

	case NGX_HTTP_INTERNAL_SERVER_ERROR: return "Internal Server Error";
	case NGX_HTTP_NOT_IMPLEMENTED: return "Not Implemented";
	case NGX_HTTP_BAD_GATEWAY: return "Bad Gateway";
	case NGX_HTTP_SERVICE_UNAVAILABLE: return "Service Unavailable";
	case NGX_HTTP_GATEWAY_TIME_OUT: return "Gateway Timeout";
	case 505: return "Http Version Not Supported";
	case 506: return "Insufficient Storage";
	case 509: return "Bandwidth Limit Exceeded";

	default: return "";
	}
}

typedef struct {
	ngx_str_t						lib;
	ngx_str_t						etc;
	ngx_str_t						dll;
	MonoDomain						*mono;
	MonoMethod						*method;
	MonoMethod						*reg;
	MonoMethod						*unreg;
} ngx_http_mono_main_conf_t;
typedef struct {
	ngx_flag_t						enabled;
	ngx_str_t						root;
	ngx_str_t						vroot;
	char							host[36];
	ngx_atomic_t					lock;
} ngx_http_mono_srv_conf_t;
typedef struct {
	ngx_flag_t						enabled;
	ngx_str_t						root;
	ngx_str_t						vroot;
	char							host[36];
	ngx_atomic_t					lock;
} ngx_http_mono_loc_conf_t;

static void *ngx_http_mono_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_mono_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_mono_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_mono_init_process(ngx_cycle_t *cycle);
static void ngx_http_mono_exit_process(ngx_cycle_t *cycle);

static char *ngx_http_mono_set_lib_and_etc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mono_srv_set_root_and_vroot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_mono_loc_set_root_and_vroot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_mono_commands[] = {

	{ ngx_string("mono_lib_and_etc"),
	NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE3,
	ngx_http_mono_set_lib_and_etc,
	NGX_HTTP_MAIN_CONF_OFFSET,
	0,
	NULL },

	{ ngx_string("mono_root_and_vroot"),
	NGX_HTTP_SRV_CONF | NGX_CONF_TAKE2,
	ngx_http_mono_srv_set_root_and_vroot,
	NGX_HTTP_SRV_CONF_OFFSET,
	0,
	NULL },

	{ ngx_string("mono_root_and_vroot"),
	NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
	ngx_http_mono_loc_set_root_and_vroot,
	NGX_HTTP_LOC_CONF_OFFSET,
	0,
	NULL },

	ngx_null_command
};
static ngx_http_module_t  ngx_http_mono_module_ctx = {
	NULL,								/* preconfiguration */
	NULL,								/* postconfiguration */

	ngx_http_mono_create_main_conf,		/* create main configuration */
	NULL,								/* init main configuration */

	ngx_http_mono_create_srv_conf,		/* create server configuration */
	NULL,								/* merge server configuration */

	ngx_http_mono_create_loc_conf,		/* create location configuration */
	NULL								/* merge location configuration */
};
ngx_module_t  ngx_http_mono_module = {
	NGX_MODULE_V1,
	&ngx_http_mono_module_ctx,      /* module context */
	ngx_http_mono_commands,         /* module directives */
	NGX_HTTP_MODULE,				/* module type */
	NULL,							/* init master */
	NULL,							/* init module */
	ngx_http_mono_init_process,		/* init process */
	NULL,							/* init thread */
	NULL,							/* exit thread */
	ngx_http_mono_exit_process,		/* exit process */
	NULL,							/* exit master */
	NGX_MODULE_V1_PADDING
};

#define GET_MONO_STR(s) mono_string_new(mono_domain_get(), (const char *)s)
#define GET_MONO_STR_LEN(s, l) mono_string_new_len(mono_domain_get(), (const char *)s, l)
#define NGX_NEW_STR_BEGIN(n, p, l, v) n = ngx_pcalloc(p, sizeof(u_char) * (l + 1));\
	if (!n) {\
		return v;\
	}
#define NGX_NEW_STR_END(n, s, l) ngx_memcpy(n, s, l)
#define NGX_NEW_STR(n, p, s, l, v) NGX_NEW_STR_BEGIN(n, p, l, v);\
	NGX_NEW_STR_END(n, s, l)
#define NGX_NEW_BUF_BEGIN(n, p, v) n = ngx_pcalloc(p, sizeof(ngx_buf_t));\
	if (!n) {\
		return v;\
	}
#define NGX_NEW_BUF_MEM_END(n, s, l) n->pos = s;\
	n->last = s + l;\
	n->memory = 1;\
	n->last_buf = 1
#define NGX_NEW_BUF_MEM(n, p, s, l, v) NGX_NEW_BUF_BEGIN(n, p, v)\
	NGX_NEW_BUF_MEM_END(n, s, l)
#define NGX_STR_SET_LEN(str, s, l) (str)->len = l;\
	(str)->data = s
#define SET_HEADER(n, v, l, k) if (v) {\
		if (!request->headers_out.n) {\
			request->headers_out.n = ngx_list_push(&request->headers_out.headers);\
			if (!request->headers_out.n) {\
				return 0;\
			}\
		}\
		request->headers_out.n->hash = 1;\
		ngx_str_set(&request->headers_out.n->key, k);\
		request->headers_out.n->value.data = v;\
		request->headers_out.n->value.len = l;\
	}

static MonoObject*
ngx_http_mono_invoke(ngx_http_mono_main_conf_t *mmcf, MonoMethod *method, MonoObject *instance, void **args)
{
	MonoObject* result;
	MonoObject* error = 0;
	//mono_domain_set(mmcf->mono, 0);
	//mono_thread_attach(mmcf->mono);
	result = mono_runtime_invoke(method, instance, args, &error);
	if (error) return 0;
	return result;
}

static void
ngx_http_mono_create_instance(ngx_http_mono_main_conf_t *mmcf, ngx_str_t root, ngx_str_t vroot, char *buf)
{
	void* args[2];
	args[0] = GET_MONO_STR(root.data);
	args[1] = GET_MONO_STR(vroot.data);

	MonoString* id = (MonoString *)ngx_http_mono_invoke(mmcf, mmcf->reg, 0, args);
	if (id) {
		int len = mono_string_length(id);
		if (len) {
			char *s = mono_string_to_utf8(id);
			if (s) {
				memcpy(buf, s, len);
				mono_free(s);
			}
		}
	}
}

static ngx_flag_t
ngx_http_mono_process(ngx_http_mono_main_conf_t *mmcf, const char *id, ngx_http_request_t *r, ngx_chain_t *pout)
{
	void* args[3];
	args[0] = GET_MONO_STR(id);
	args[1] = &r;
	args[2] = &pout;
	MonoObject* result = ngx_http_mono_invoke(mmcf, mmcf->method, 0, args);
	if (result) return (ngx_flag_t)*(int*)mono_object_unbox(result);
	return 0;
}

static void
ngx_http_mono_dispose_instance(ngx_http_mono_main_conf_t *mmcf, char *id)
{
	void* args[1];
	args[0] = GET_MONO_STR(id);
	ngx_http_mono_invoke(mmcf, mmcf->unreg, 0, args);
	id[0] = '\0';
}

#define MONO_PROCESS_REQUEST(conf) if (!conf->host[0]) { \
		ngx_rwlock_wlock(&conf->lock); \
		if (!conf->host[0]) { \
			ngx_http_mono_create_instance(mmcf, conf->root, conf->vroot, &conf->host[0]); \
		} \
		ngx_rwlock_unlock(&conf->lock); \
	} \
	if (conf->host[0]) { \
		ngx_rwlock_rlock(&conf->lock); \
		if (conf->host[0]) { \
			handle = ngx_http_mono_process(mmcf, &conf->host[0], r, pout); \
		} \
		ngx_rwlock_unlock(&conf->lock); \
		if (!handle && conf->host[0]) { \
			ngx_rwlock_wlock(&conf->lock); \
			if (conf->host[0]) { \
				ngx_http_mono_dispose_instance(mmcf, &conf->host[0]); \
			} \
			ngx_rwlock_unlock(&conf->lock); \
		} \
	}

static MonoString *GetRequestHeader(ngx_http_request_t *request)
{
	ngx_uint_t i;
	ngx_list_part_t *part;
	ngx_table_elt_t *header;

	size_t length = 0;

	length += request->method_name.len + 1;
	length += request->unparsed_uri.len + 1;
	length += request->http_protocol.len + 1;

	for (part = &request->headers_in.headers.part; part; part = part->next) {
		header = part->elts;
		for (i = 0; i < part->nelts; ++i) {
			length += header[i].key.len + 1;
			length += header[i].value.len + 1;
		}
	}

	u_char *NGX_NEW_STR_BEGIN(temp, request->pool, length, GET_MONO_STR(""));
	u_char *ptr = temp;

	ptr = ngx_copy(ptr, request->method_name.data, request->method_name.len);
	ptr = ngx_copy(ptr, "\n", 1);
	ptr = ngx_copy(ptr, request->unparsed_uri.data, request->unparsed_uri.len);
	ptr = ngx_copy(ptr, "\n", 1);
	ptr = ngx_copy(ptr, request->http_protocol.data, request->http_protocol.len);
	ptr = ngx_copy(ptr, "\n", 1);

	for (part = &request->headers_in.headers.part; part; part = part->next) {
		header = part->elts;
		for (i = 0; i < part->nelts; ++i) {
			ptr = ngx_copy(ptr, header[i].key.data, header[i].key.len);
			ptr = ngx_copy(ptr, ":", 1);
			ptr = ngx_copy(ptr, header[i].value.data, header[i].value.len);
			ptr = ngx_copy(ptr, "\n", 1);
		}
	}

	return GET_MONO_STR(temp);
}
static MonoString *GetServerVariable(ngx_http_request_t *request, MonoString* name)
{
	int length = mono_string_length(name);
	u_char *NGX_NEW_STR_BEGIN(temp, request->pool, length, 0);
	char *tmp = mono_string_to_utf8(name);
	NGX_NEW_STR_END(temp, tmp, length);
	mono_free(tmp);

	ngx_str_t var;
	var.data = temp;
	var.len = length;
	ngx_int_t key = ngx_hash_strlow(var.data, var.data, var.len);
	ngx_http_variable_value_t *value = ngx_http_get_variable(request, &var, key);
	if (value && !value->not_found)
		return GET_MONO_STR_LEN(value->data, value->len);

	return 0;
}
static int32_t GetInputDataType(ngx_http_request_t *request)
{
	if (request->request_body) {
		if (request->request_body->temp_file)
			return 2;

		if (request->request_body->bufs)
			return 1;
	}
	return 0;
}
static MonoArray *GetInputData(ngx_http_request_t *request)
{
	if (request->request_body && request->request_body->bufs) {
		ngx_chain_t * bufs;

		off_t size = 0;

		bufs = request->request_body->bufs;
		for (bufs = request->request_body->bufs; bufs; bufs = bufs->next)
			size += bufs->buf->last - bufs->buf->pos;

		if (size > 0) {
			MonoArray* arr = mono_array_new(mono_domain_get(), mono_get_byte_class(), (uintptr_t)size);
			u_char *ptr = mono_array_addr(arr, u_char, 0);

			bufs = request->request_body->bufs;
			for (bufs = request->request_body->bufs; bufs; bufs = bufs->next)
				ptr = ngx_copy(ptr, bufs->buf->pos, bufs->buf->last - bufs->buf->pos);

			return arr;
		}
		else {
			return mono_array_new(mono_domain_get(), mono_get_byte_class(), 0);
		}
	}
	return 0;
}
static int32_t ReadInputData(ngx_http_request_t *request, MonoArray *buffer, int32_t size, int32_t offset)
{
	if (request->request_body && request->request_body->temp_file) {
		return ngx_read_file(&request->request_body->temp_file->file, mono_array_addr(buffer, u_char, 0), size, offset);
	}
	return 0;
}

static int32_t SetStatus(ngx_http_request_t *request, int32_t status)
{
	request->headers_out.status = (ngx_uint_t)status;

	return 1;
}
static int32_t SetHeader(ngx_http_request_t *request, int32_t index, MonoString* value)
{
	u_char *pv = 0;
	int vlen = 0;

	if (value) {
		vlen = mono_string_length(value);
		NGX_NEW_STR_BEGIN(pv, request->pool, vlen, 0);
		if (vlen) {
			char *v = mono_string_to_utf8(value);
			NGX_NEW_STR_END(pv, v, vlen);
			mono_free(v);
		}
	}

	switch (index) {
	case 0://Cache-Control
		if (pv) {
			if (ngx_array_init(&request->headers_out.cache_control, request->pool, 1, sizeof(ngx_table_elt_t *)) != NGX_OK)
				return 0;
			ngx_table_elt_t **ccp = ngx_array_push(&request->headers_out.cache_control);
			if (!ccp)
				return 0;
			ngx_table_elt_t *cc = ngx_list_push(&request->headers_out.headers);
			if (!cc)
				return 0;

			ngx_str_set(&cc->key, "Cache-Control");
			NGX_STR_SET_LEN(&cc->value, pv, vlen);
			*ccp = cc;
		}
		break;
		//case 1://Connection
		//case 2://Date
		//case 3://Keep-Alive
		//case 4://Pragma
		//case 5://Trailer
		//case 6://Transfer-Encoding
		//case 7://Upgrade
		//case 8://Via
		//case 9://Warning
		//case 10://Allow
		//case 11://Content-Length
	case 12://Content-Type
		NGX_STR_SET_LEN(&request->headers_out.content_type, pv, vlen);
		if (ngx_strstr(pv, "; charset="))
			request->headers_out.content_type_len = 0;
		else
			request->headers_out.content_type_len = vlen;
		break;
		//case 13://Content-Encoding
		//case 14://Content-Language
		//case 15://Content-Location
		//case 16://Content-MD5
	case 17://Content-Range
		SET_HEADER(content_range, pv, vlen, "Content-Range");
		break;
	case 18://Expires
		SET_HEADER(expires, pv, vlen, "Expires");
		break;
	case 19://Last-Modified
		SET_HEADER(last_modified, pv, vlen, "Last-Modified");
		break;
	case 20://Accept-Ranges
		SET_HEADER(accept_ranges, pv, vlen, "Accept-Ranges");
		break;
		//case 21://Age
	case 22://ETag
		SET_HEADER(etag, pv, vlen, "ETag");
		break;
	case 23://Location
		SET_HEADER(location, pv, vlen, "Location");
		break;
		//case 24://Proxy-Authenticate
		//case 25://Retry-After
		//case 26://Server
	case 27://Set-Cookie
		if (pv) {
			ngx_table_elt_t *h = ngx_list_push(&request->headers_out.headers);
			if (h == NULL)
				return 0;
			h->hash = 1;
			ngx_str_set(&h->key, "Set-Cookie");
			NGX_STR_SET_LEN(&h->value, pv, vlen);
		}
		break;
		//case 28://Vary
	case 29://WWW-Authenticate
		SET_HEADER(www_authenticate, pv, vlen, "WWW-Authenticate");
		break;
	}
	return 0;
}
static int32_t SetUnknownHeader(ngx_http_request_t *request, MonoString* name, MonoString* value)
{
	if (name && value) {
		int nlen = mono_string_length(name);
		if (nlen) {
			ngx_table_elt_t *h = ngx_list_push(&request->headers_out.headers);
			if (h == NULL)
				return 0;

			u_char *NGX_NEW_STR_BEGIN(pn, request->pool, nlen, 0);
			int vlen = mono_string_length(value);
			u_char *NGX_NEW_STR_BEGIN(pv, request->pool, vlen, 0);

			char *n = mono_string_to_utf8(name);
			NGX_NEW_STR_END(pn, n, nlen);
			mono_free(n);
			if (vlen) {
				char *v = mono_string_to_utf8(value);
				NGX_NEW_STR_END(pv, v, vlen);
				mono_free(v);
			}

			h->hash = 1;
			NGX_STR_SET_LEN(&h->key, pn, nlen);
			NGX_STR_SET_LEN(&h->value, pv, vlen);

			return 1;
		}
	}
	return 0;
}
static int32_t SendContent(ngx_http_request_t *request, ngx_chain_t *response, MonoArray* content, int32_t size)
{
	u_char *NGX_NEW_STR(temp, request->pool, mono_array_addr(content, u_char, 0), size, 0);
	ngx_buf_t *NGX_NEW_BUF_MEM(buf, request->pool, temp, size, 0);
	response->buf = buf;
	response->next = 0;
	request->headers_out.content_length_n = size;
	return 0;
}
static int32_t SetError(ngx_http_request_t *request, ngx_chain_t *response, int32_t status, MonoString* message)
{
	request->headers_out.status = (ngx_uint_t)status;
	ngx_str_set(&request->headers_out.content_type, DEFAULT_CONTENT_TYPE);
	ngx_str_set(&request->headers_out.charset, DEFAULT_CONTENT_CHARSET);

	off_t length = 0;
	u_char *str = 0;
	if (message) {
		length = mono_string_length(message);
		if (length > 0) {
			NGX_NEW_STR_BEGIN(str, request->pool, (size_t)length, 0);
			char *msg = mono_string_to_utf8(message);
			NGX_NEW_STR_END(str, msg, (size_t)length);
			mono_free(msg);
		}
	}

	if (!str) {
		NGX_NEW_STR(str, request->pool, "", 0, 0);
	}

	length += 192;
	u_char *NGX_NEW_STR_BEGIN(temp, request->pool, (size_t)length, 0);
	const u_char *status_str = (const u_char *)status_code_string(status);
	ngx_snprintf(temp, (size_t)length, ERROR_HTML, status_str, status_str, status, str);

	length = ngx_strlen(temp);
	ngx_buf_t *NGX_NEW_BUF_MEM(buf, request->pool, temp, length, 0);

	response->buf = buf;
	response->next = 0;
	request->headers_out.content_length_n = length;

	return 1;
}
static int32_t SendFile(ngx_http_request_t *request, ngx_chain_t *response, MonoString* filename, int64_t offset, int64_t size)
{
	if (filename) {
		int len = mono_string_length(filename);
		if (len > 0) {
			ngx_http_core_loc_conf_t *clcf = clcf = ngx_http_get_module_loc_conf(request, ngx_http_core_module);
			if (!clcf)
				return 0;

			u_char *NGX_NEW_STR_BEGIN(temp, request->pool, len, 0);
			char *tmp = mono_string_to_utf8(filename);
			NGX_NEW_STR_END(temp, tmp, len);
			mono_free(tmp);

			ngx_str_t path;
			path.data = temp;
			path.len = len;

			ngx_open_file_info_t of;
			ngx_memzero(&of, sizeof(ngx_open_file_info_t));

			if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, request->pool) != NGX_OK)
				return 0;
			if (of.is_dir)
				return 0;
#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

			if (!of.is_file)
				return 0;
#endif

			request->headers_out.status = NGX_HTTP_OK;
			request->headers_out.content_length_n = of.size;
			request->headers_out.last_modified_time = of.mtime;

			if (ngx_http_set_etag(request) != NGX_OK)
				return 0;

			if (of.size == 0)
				return 1;

			request->allow_ranges = 1;

			/* we need to allocate all before the header would be sent */

			ngx_buf_t *b = ngx_pcalloc(request->pool, sizeof(ngx_buf_t));
			if (!b)
				return 0;

			b->file = ngx_pcalloc(request->pool, sizeof(ngx_file_t));
			if (!b->file)
				return 0;

			b->file_pos = 0;
			b->file_last = of.size;

			b->in_file = 1;
			b->last_buf = 1;
			b->last_in_chain = 1;

			b->file->fd = of.fd;
			b->file->name = path;
			b->file->directio = of.is_directio;

			response->buf = b;
			response->next = NULL;

			return 1;
		}
	}
	return 0;
}

static void *
ngx_http_mono_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_mono_main_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mono_main_conf_t));
	if (conf == NULL)
		return NULL;

	return conf;
}
static void *
ngx_http_mono_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_mono_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mono_srv_conf_t));
	if (conf == NULL)
		return NULL;

	return conf;
}
static void *
ngx_http_mono_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mono_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mono_loc_conf_t));
	if (conf == NULL)
		return NULL;

	return conf;
}

static ngx_int_t
ngx_http_mono_init_process(ngx_cycle_t *cycle)
{
	ngx_http_mono_main_conf_t *mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_mono_module);
	if (mmcf && !mmcf->mono) {
		mono_set_dirs((const char *)mmcf->lib.data, (const char *)mmcf->etc.data);
		mono_config_parse(0);
		mmcf->mono = mono_jit_init((const char *)mmcf->dll.data);

		if (!mmcf->mono) {
#ifdef CONSOLE
			printf("failed to initialize Mono VM\r\n");
#endif
			return NGX_ERROR;
		}

		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::GetRequestHeader", (const void*)GetRequestHeader);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::GetServerVariable", (const void*)GetServerVariable);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::GetInputDataType", (const void*)GetInputDataType);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::GetInputData", (const void*)GetInputData);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::ReadInputData", (const void*)ReadInputData);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::SetStatus", (const void*)SetStatus);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::SetHeader", (const void*)SetHeader);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::SetUnknownHeader", (const void*)SetUnknownHeader);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::SendContent", (const void*)SendContent);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::SetError", (const void*)SetError);
		mono_add_internal_call("Cnaws.Web.Hosting.MonoInternal::SendFile", (const void*)SendFile);

		MonoAssembly* assembly = mono_domain_assembly_open(mmcf->mono, (const char *)mmcf->dll.data);
		if (!assembly) {
#ifdef CONSOLE
			printf("failed to open Mono assembly \"%s\"\r\n", (const char *)mmcf->dll.data);
#endif
			return NGX_ERROR;
		}
		MonoImage* image = mono_assembly_get_image(assembly);
		if (!image) {
#ifdef CONSOLE
			printf("failed to get Mono assembly image \"%s\"\r\n", (const char *)mmcf->dll.data);
#endif
			return NGX_ERROR;
		}
		MonoClass* mclass = mono_class_from_name(image, "Cnaws.Web.Hosting", "Mono");
		if (!mclass) {
#ifdef CONSOLE
			printf("failed to get Mono class \"Cnaws.Web.Hosting.Mono\"\r\n");
#endif
			return NGX_ERROR;
		}
		mmcf->reg = mono_class_get_method_from_name(mclass, "Register", 2);
		if (!mmcf->reg) {
#ifdef CONSOLE
			printf("failed to get Mono method \"Cnaws.Web.Hosting.Mono.Register\"\r\n");
#endif
			return NGX_ERROR;
		}
		mmcf->method = mono_class_get_method_from_name(mclass, "ProcessRequest", 3);
		if (!mmcf->method) {
#ifdef CONSOLE
			printf("failed to get Mono method \"Cnaws.Web.Hosting.Mono.ProcessRequest\"\r\n");
#endif
			return NGX_ERROR;
		}
		mmcf->unreg = mono_class_get_method_from_name(mclass, "Unregister", 1);
		if (!mmcf->unreg) {
#ifdef CONSOLE
			printf("failed to get Mono method \"Cnaws.Web.Hosting.Mono.Unregister\"\r\n");
#endif
			return NGX_ERROR;
		}

#ifdef CONSOLE
		printf("Mono initialized\r\n");
#endif
	}

	return NGX_OK;
}
static void
ngx_http_mono_exit_process(ngx_cycle_t *cycle)
{
	ngx_http_mono_main_conf_t *mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_mono_module);
	if (mmcf && mmcf->mono) {
		mono_jit_cleanup(mmcf->mono);

#ifdef CONSOLE
		printf("Mono cleanuped\r\n");
#endif
	}
}

static ngx_int_t
ngx_http_mono_request_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_chain_t out;
	ngx_flag_t handle = 0;

	ngx_chain_t *pout = &out;

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, DEFAULT_CONTENT_TYPE);
	ngx_str_set(&r->headers_out.charset, DEFAULT_CONTENT_CHARSET);
	r->headers_out.content_length_n = 0;

	ngx_http_mono_main_conf_t *mmcf = ngx_http_get_module_main_conf(r, ngx_http_mono_module);
	if (mmcf && mmcf->mono) {
		ngx_http_mono_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mono_module);
		if (mlcf && mlcf->enabled) {
			MONO_PROCESS_REQUEST(mlcf)
		}
		else {
			ngx_http_mono_srv_conf_t *mscf = ngx_http_get_module_srv_conf(r, ngx_http_mono_module);
			if (mscf && mscf->enabled) {
				MONO_PROCESS_REQUEST(mscf)
			}
		}
	}

	if (!handle) {
#ifdef CONSOLE
		printf("call method ProcessRequest faild\r\n");
#endif

		if (!SetError(r, &out, NGX_HTTP_BAD_REQUEST, 0))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((r->method & NGX_HTTP_HEAD) || (r->headers_out.content_length_n == 0))
		return ngx_http_send_header(r);

	rc = ngx_http_send_header(r);
	if (rc != NGX_OK)
		return rc;

	return ngx_http_output_filter(r, &out);
}
static void
ngx_http_mono_request_post_handler(ngx_http_request_t *r)
{
	ngx_int_t result = NGX_HTTP_INTERNAL_SERVER_ERROR;
	if (r->request_body)
		result = ngx_http_mono_request_handler(r);
	ngx_http_finalize_request(r, result);
}
static ngx_int_t
ngx_http_mono_handler(ngx_http_request_t *r)
{
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST | NGX_HTTP_HEAD | NGX_HTTP_OPTIONS)))
		return NGX_HTTP_NOT_ALLOWED;

	if (r->method & NGX_HTTP_OPTIONS) {
		ngx_int_t rc;
		ngx_chain_t out;
		ngx_table_elt_t *h;

		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL)
			return NGX_ERROR;
		h->hash = 1;
		ngx_str_set(&h->key, "Access-Control-Allow-Origin");
		ngx_str_set(&h->value, "*");

		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL)
			return NGX_ERROR;
		h->hash = 1;
		ngx_str_set(&h->key, "Access-Control-Allow-Methods");
		ngx_str_set(&h->value, "GET, POST, HEAD, OPTIONS");

		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL)
			return NGX_ERROR;
		h->hash = 1;
		ngx_str_set(&h->key, "Access-Control-Allow-Headers");
		ngx_str_set(&h->value, "Authorization, Origin, X-Requested-With, Content-Type, Accept");

		h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL)
			return NGX_ERROR;
		h->hash = 1;
		ngx_str_set(&h->key, "Access-Control-Max-Age");
		ngx_str_set(&h->value, "86400");

		if (!SetError(r, &out, NGX_HTTP_OK, 0))
			return NGX_HTTP_INTERNAL_SERVER_ERROR;

		rc = ngx_http_send_header(r);
		if (rc != NGX_OK)
			return rc;

		return ngx_http_output_filter(r, &out);
	}

	if (r->method & NGX_HTTP_POST) {
		ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_mono_request_post_handler);
		if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
			return rc;

		return NGX_DONE;
	}

	return ngx_http_mono_request_handler(r);
}

static char *
ngx_http_mono_set_lib_and_etc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_mono_main_conf_t *mmcf = conf;
	ngx_str_t *value;
	size_t len;
	u_char *p;

	if (mmcf->lib.len != 0 && mmcf->etc.len != 0 && mmcf->dll.len != 0) {
		return "is duplicate";
	}

	value = cf->args->elts;

	len = value[1].len;
	p = value[1].data;
	if (len && p[len - 1] == OS_PATH_CHAR)
		--len;
	mmcf->lib.data = ngx_pcalloc(cf->pool, (len + 1) * sizeof(u_char));
	if (!mmcf->lib.data) {
		return NGX_CONF_ERROR;
	}
	if (len) {
		ngx_memcpy(mmcf->lib.data, p, len);
	}
	mmcf->lib.len = len;

	len = value[2].len;
	p = value[2].data;
	if (len && p[len - 1] == OS_PATH_CHAR)
		--len;
	mmcf->etc.data = ngx_pcalloc(cf->pool, (len + 1) * sizeof(u_char));
	if (!mmcf->etc.data) {
		return NGX_CONF_ERROR;
	}
	if (len) {
		ngx_memcpy(mmcf->etc.data, p, len);
	}
	mmcf->etc.len = len;

	len = value[3].len;
	p = value[3].data;
	if (len && p[len - 1] == OS_PATH_CHAR)
		--len;
	mmcf->dll.data = ngx_pcalloc(cf->pool, (len + 22 + 1) * sizeof(u_char));
	if (!mmcf->dll.data) {
		return NGX_CONF_ERROR;
	}
	if (len) {
		ngx_memcpy(mmcf->dll.data, p, len);
	}
	ngx_memcpy(mmcf->dll.data + len, OS_PATH_STRING"Cnaws.Web.Hosting.dll", 22);
	len += 22;
	mmcf->dll.len = len;

	return NGX_CONF_OK;
}
static char *
ngx_http_mono_srv_set_root_and_vroot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_mono_srv_conf_t *mscf = conf;
	ngx_str_t *value;
	size_t len;
	u_char *p;
	ngx_http_core_loc_conf_t *clcf;

	if (mscf->enabled) {
		return "is duplicate";
	}

	value = cf->args->elts;

	len = value[1].len;
	p = value[1].data;
	if (len && p[len - 1] == OS_PATH_CHAR)
		--len;
	mscf->root.data = ngx_pcalloc(cf->pool, (len + 1 + 1) * sizeof(u_char));
	if (!mscf->root.data) {
		return NGX_CONF_ERROR;
	}
	if (len) {
		ngx_memcpy(mscf->root.data, p, len);
	}
	mscf->root.data[len] = OS_PATH_CHAR;
	len += 1;
	mscf->root.len = len;

	len = value[2].len;
	p = value[2].data;
	if (len && p[len - 1] == '/')
		--len;
	mscf->vroot.data = ngx_pcalloc(cf->pool, (len + 1 + 1) * sizeof(u_char));
	if (!mscf->vroot.data) {
		return NGX_CONF_ERROR;
	}
	if (len) {
		ngx_memcpy(mscf->vroot.data, p, len);
	}
	mscf->vroot.data[len] = '/';
	len += 1;
	mscf->vroot.len = len;

	mscf->enabled = 1;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	if (!clcf) {
		return NGX_CONF_ERROR;
	}
	clcf->handler = ngx_http_mono_handler;

	return NGX_CONF_OK;
}
static char *
ngx_http_mono_loc_set_root_and_vroot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_mono_loc_conf_t *mlcf = conf;
	ngx_str_t *value;
	size_t len;
	u_char *p;
	ngx_http_core_loc_conf_t *clcf;

	if (mlcf->enabled) {
		return "is duplicate";
	}

	value = cf->args->elts;

	len = value[1].len;
	p = value[1].data;
	if (len && p[len - 1] == OS_PATH_CHAR)
		--len;
	mlcf->root.data = ngx_pcalloc(cf->pool, (len + 1 + 1) * sizeof(u_char));
	if (!mlcf->root.data) {
		return NGX_CONF_ERROR;
	}
	if (len) {
		ngx_memcpy(mlcf->root.data, p, len);
	}
	mlcf->root.data[len] = OS_PATH_CHAR;
	len += 1;
	mlcf->root.len = len;

	len = value[2].len;
	p = value[2].data;
	if (len && p[len - 1] == '/')
		--len;
	mlcf->vroot.data = ngx_pcalloc(cf->pool, (len + 1 + 1) * sizeof(u_char));
	if (!mlcf->vroot.data) {
		return NGX_CONF_ERROR;
	}
	if (len) {
		ngx_memcpy(mlcf->vroot.data, p, len);
	}
	mlcf->vroot.data[len] = '/';
	len += 1;
	mlcf->vroot.len = len;

	mlcf->enabled = 1;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	if (!clcf) {
		return NGX_CONF_ERROR;
	}
	clcf->handler = ngx_http_mono_handler;

	return NGX_CONF_OK;
}
