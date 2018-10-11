#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_generate_keypair_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_generate_keypair_t;

typedef struct ms_get_public_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pub_key;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_get_public_key_t;

typedef struct ms_show_private_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_show_private_key_t;

typedef struct ms_sign_message_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
	uint8_t* ms_hashed_message;
	uint8_t* ms_signature;
} ms_sign_message_t;

typedef struct ms_t_global_init_ecall_t {
	uint64_t ms_id;
	uint8_t* ms_path;
	size_t ms_len;
} ms_t_global_init_ecall_t;

typedef struct ms_u_stdin_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stdin_ocall_t;

typedef struct ms_u_stdout_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stdout_ocall_t;

typedef struct ms_u_stderr_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stderr_ocall_t;

typedef struct ms_u_backtrace_open_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_pathname;
	int ms_flags;
} ms_u_backtrace_open_ocall_t;

typedef struct ms_u_backtrace_close_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_backtrace_close_ocall_t;

typedef struct ms_u_backtrace_fcntl_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
	int ms_arg;
} ms_u_backtrace_fcntl_ocall_t;

typedef struct ms_u_backtrace_mmap_ocall_t {
	void* ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
	int ms_prot;
	int ms_flags;
	int ms_fd;
	int64_t ms_offset;
} ms_u_backtrace_mmap_ocall_t;

typedef struct ms_u_backtrace_munmap_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
} ms_u_backtrace_munmap_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_generate_keypair(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_keypair_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generate_keypair_t* ms = SGX_CAST(ms_generate_keypair_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		if ((_in_sealed_log = (uint8_t*)malloc(_len_sealed_log)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_log, 0, _len_sealed_log);
	}

	ms->ms_retval = generate_keypair(_in_sealed_log, _tmp_sealed_log_size);
err:
	if (_in_sealed_log) {
		memcpy(_tmp_sealed_log, _in_sealed_log, _len_sealed_log);
		free(_in_sealed_log);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_public_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_public_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_public_key_t* ms = SGX_CAST(ms_get_public_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_pub_key = ms->ms_pub_key;
	size_t _len_pub_key = 64 * sizeof(uint8_t);
	uint8_t* _in_pub_key = NULL;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	if (sizeof(*_tmp_pub_key) != 0 &&
		64 > (SIZE_MAX / sizeof(*_tmp_pub_key))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_pub_key, _len_pub_key);
	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pub_key != NULL && _len_pub_key != 0) {
		if ((_in_pub_key = (uint8_t*)malloc(_len_pub_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pub_key, 0, _len_pub_key);
	}
	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		_in_sealed_log = (uint8_t*)malloc(_len_sealed_log);
		if (_in_sealed_log == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_log, _tmp_sealed_log, _len_sealed_log);
	}

	ms->ms_retval = get_public_key(_in_pub_key, _in_sealed_log, _tmp_sealed_log_size);
err:
	if (_in_pub_key) {
		memcpy(_tmp_pub_key, _in_pub_key, _len_pub_key);
		free(_in_pub_key);
	}
	if (_in_sealed_log) free(_in_sealed_log);

	return status;
}

static sgx_status_t SGX_CDECL sgx_show_private_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_show_private_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_show_private_key_t* ms = SGX_CAST(ms_show_private_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		_in_sealed_log = (uint8_t*)malloc(_len_sealed_log);
		if (_in_sealed_log == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_log, _tmp_sealed_log, _len_sealed_log);
	}

	ms->ms_retval = show_private_key(_in_sealed_log, _tmp_sealed_log_size);
err:
	if (_in_sealed_log) free(_in_sealed_log);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sign_message(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sign_message_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sign_message_t* ms = SGX_CAST(ms_sign_message_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;
	uint8_t* _tmp_hashed_message = ms->ms_hashed_message;
	size_t _len_hashed_message = 32 * sizeof(uint8_t);
	uint8_t* _in_hashed_message = NULL;
	uint8_t* _tmp_signature = ms->ms_signature;
	size_t _len_signature = 65 * sizeof(uint8_t);
	uint8_t* _in_signature = NULL;

	if (sizeof(*_tmp_hashed_message) != 0 &&
		32 > (SIZE_MAX / sizeof(*_tmp_hashed_message))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_signature) != 0 &&
		65 > (SIZE_MAX / sizeof(*_tmp_signature))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);
	CHECK_UNIQUE_POINTER(_tmp_hashed_message, _len_hashed_message);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		_in_sealed_log = (uint8_t*)malloc(_len_sealed_log);
		if (_in_sealed_log == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_log, _tmp_sealed_log, _len_sealed_log);
	}
	if (_tmp_hashed_message != NULL && _len_hashed_message != 0) {
		_in_hashed_message = (uint8_t*)malloc(_len_hashed_message);
		if (_in_hashed_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_hashed_message, _tmp_hashed_message, _len_hashed_message);
	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ((_in_signature = (uint8_t*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}

	ms->ms_retval = sign_message(_in_sealed_log, _tmp_sealed_log_size, _in_hashed_message, _in_signature);
err:
	if (_in_sealed_log) free(_in_sealed_log);
	if (_in_hashed_message) free(_in_hashed_message);
	if (_in_signature) {
		memcpy(_tmp_signature, _in_signature, _len_signature);
		free(_in_signature);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_init_ecall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_global_init_ecall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_global_init_ecall_t* ms = SGX_CAST(ms_t_global_init_ecall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_path = ms->ms_path;
	size_t _tmp_len = ms->ms_len;
	size_t _len_path = _tmp_len;
	uint8_t* _in_path = NULL;

	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_path != NULL && _len_path != 0) {
		_in_path = (uint8_t*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_path, _tmp_path, _len_path);
	}

	t_global_init_ecall(ms->ms_id, (const uint8_t*)_in_path, _tmp_len);
err:
	if (_in_path) free((void*)_in_path);

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_exit_ecall(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	t_global_exit_ecall();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_generate_keypair, 0},
		{(void*)(uintptr_t)sgx_get_public_key, 0},
		{(void*)(uintptr_t)sgx_show_private_key, 0},
		{(void*)(uintptr_t)sgx_sign_message, 0},
		{(void*)(uintptr_t)sgx_t_global_init_ecall, 0},
		{(void*)(uintptr_t)sgx_t_global_exit_ecall, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[13][6];
} g_dyn_entry_table = {
	13,
	{
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL u_stdin_ocall(size_t* retval, void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stdin_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stdin_ocall_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stdin_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stdin_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stdout_ocall(size_t* retval, const void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stdout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stdout_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stdout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stdout_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stderr_ocall(size_t* retval, const void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stderr_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stderr_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stderr_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stderr_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_open_ocall(int* retval, int* error, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_backtrace_open_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_open_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_open_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_open_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		memcpy(__tmp, pathname, _len_pathname);
		__tmp = (void *)((size_t)__tmp + _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_close_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_backtrace_close_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_close_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_close_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_close_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_fcntl_ocall(int* retval, int* error, int fd, int cmd, int arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_backtrace_fcntl_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_fcntl_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_fcntl_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_fcntl_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_mmap_ocall(void** retval, int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_backtrace_mmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_mmap_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_mmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_mmap_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_start = SGX_CAST(void*, start);
	ms->ms_length = length;
	ms->ms_prot = prot;
	ms->ms_flags = flags;
	ms->ms_fd = fd;
	ms->ms_offset = offset;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_munmap_ocall(int* retval, int* error, void* start, size_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_backtrace_munmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_munmap_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_munmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_munmap_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_start = SGX_CAST(void*, start);
	ms->ms_length = length;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}
