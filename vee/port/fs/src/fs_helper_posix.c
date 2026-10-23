/*
 * C
 * Copyright 2015-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLFS implementation over POSIX API.
 * @author MicroEJ Developer Team
 * @version 3.0.6
 */

/* Includes ------------------------------------------------------------------*/

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <time.h>
#include <utime.h>
#include <dirent.h>
#include "LLFS_impl.h"
#include "LLFS_File_impl.h"
#include "microej_async_worker.h"
#include "fs_helper.h"
#include "fs_configuration.h"
#include "fs_helper_posix_configuration.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLFS_LOG_MODULE_NAME, LLFS_LOG_LEVEL)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sanity check between the expected version of the configuration and the actual version of
 * the configuration.
 * If an error is raised here, it means that a new version of the CCO has been installed and
 * the configuration fs_configuration.h must be updated based on the one provided
 * by the new CCO version.
 */
#if FS_CONFIGURATION_VERSION != 1
  #error "Version of the configuration file fs_configuration.h is not compatible with this implementation."
#endif

#if FS_HELPER_POSIX_CONFIGURATION_H_VERSION != 1
  #error "Version of the configuration file fs_helper_posix_configuration.h is not compatible with this implementation."
#endif

#define LLFS_NORMAL_PERMISSIONS (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

static void LLFS_File_IMPL_buffered_read(FILE *file, uint8_t *data, int32_t length, FS_write_read_t *params);
static void LLFS_File_IMPL_buffered_write(FILE *file, uint8_t *data, int32_t length, FS_write_read_t *params);
static void LLFS_File_IMPL_regular_read(int file_desc, uint8_t *data, int32_t length, FS_write_read_t *params);
static void LLFS_File_IMPL_regular_write(int file_desc, uint8_t *data, int32_t length, FS_write_read_t *params);
static void LLFS_File_IMPL_get_available_data_IFCHR(int file_desc, FS_available_t *params);
static void LLFS_File_IMPL_gett_available_data(FILE *file, uint64_t file_size, FS_available_t *params);

/**
 * @brief Records the errno of a failed C library call in the job. The exception is thrown on the VM thread,
 * by <code>LLFS_throw_job_error</code>.
 */
#define FS_SET_ERRNO_ERROR(params)        \
		do {                              \
			(params)->result = LLFS_NOK;  \
			(params)->error_code = errno; \
		} while (0)

/*
 * This method check if a file exist on the file system.
 * return 1 when the file exists, 0 otherwise.
 */
static int FS_file_exists(const char *path) {
	FILE *file;
	if ((file = fopen(path, "r")) != NULL) {
		fclose(file);
		return 1;
	}
	return 0;
}

void LLFS_IMPL_get_last_modified_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_last_modified_t *params = (FS_last_modified_t *)job->params;
	char *path = (char *)&params->path;
	LLFS_date_t *out_date = &params->date;

	jint fs_err;
	struct stat buffer;
	struct tm *date = NULL;
	params->result = LLFS_NOK; // error by default

	fs_err = stat(path, &buffer);

	if (fs_err == 0) {
		date = localtime(&buffer.st_mtime);
		if (date != NULL) {
			out_date->millisecond = 0; // set to zero to avoid getting garbage value
			out_date->second = date->tm_sec;
			out_date->minute = date->tm_min;
			out_date->hour = date->tm_hour;
			out_date->day = date->tm_mday;
			out_date->month = date->tm_mon;
			out_date->year = date->tm_year + 1900;
			params->result = LLFS_OK;
		}
	}
}

void LLFS_IMPL_set_read_only_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path_operation_t *params = (FS_path_operation_t *)job->params;
	char *path = (char *)&params->path;
	struct stat buffer;

	params->result = LLFS_NOK; // error by default

	int fs_err = stat(path, &buffer);
	if (fs_err == 0) {
		fs_err = chmod(path, buffer.st_mode & ~(S_IWUSR | S_IWGRP | S_IWOTH));

		if (fs_err == 0) {
			//success
			params->result = LLFS_OK;
		}
	}

	VEEPORT_LOGGER_LOG_DBG("readonly set on %s (status %d err %d errno \"%s\")", path, params->result, fs_err,
	                       strerror(errno));
}

void LLFS_IMPL_create_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_create_t *params = (FS_create_t *)job->params;
	char *path = (char *)&params->path;

	params->result = LLFS_NOK; // error by default

	if (FS_file_exists(path)) {
		params->result = LLFS_NOT_CREATED;
		return;
	}

	FILE *file = fopen(path, "w");

	/* test return function */
	if (file != NULL) {
		if (fclose(file) == 0) {
			params->result = LLFS_OK;  // success
		} else {
			FS_SET_ERRNO_ERROR(params);
		}
	} else {
		FS_SET_ERRNO_ERROR(params);
	}

	VEEPORT_LOGGER_LOG_DBG("create file %s (status %d)", path, params->result);
}

void LLFS_IMPL_open_directory_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path_operation_t *params = (FS_path_operation_t *)job->params;
	char *path = (char *)&params->path;

	params->result = LLFS_NOK; // error by default

	DIR *dir = NULL;

	dir = opendir(path);
	if (dir != NULL) {
		params->result = (int32_t)dir;
	}

	VEEPORT_LOGGER_LOG_DBG("open dir %s (status %d %x errno \"%s\")", path, params->result, params->result,
	                       strerror(errno));
}

void LLFS_IMPL_read_directory_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_read_directory_t *params = (FS_read_directory_t *)job->params;
	int32_t directory_ID = params->directory_ID;
	char *path = (char *)&params->path;

	params->result = LLFS_NOK; // error by default

	struct dirent *entry = readdir((DIR *)directory_ID);
	if (entry != NULL) {
		char *entry_name = (char *)entry->d_name;
		if (strlen(entry_name) < sizeof(params->path)) {
			strcpy(path, entry_name);
			params->result = LLFS_OK;
		}
	}

	VEEPORT_LOGGER_LOG_DBG("read dir result %s (status %d)", path, params->result);
}

void LLFS_IMPL_close_directory_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_close_directory_t *params = (FS_close_directory_t *)job->params;
	int32_t directory_ID = params->directory_ID;

	int fs_err = closedir((DIR *)directory_ID);

	if (fs_err == 0) {
		params->result = LLFS_OK;
	} else {
		params->result = LLFS_NOK;
	}

	VEEPORT_LOGGER_LOG_DBG("close dir (status %d err %d errno \"%s\")", params->result, fs_err, strerror(errno));
}

void LLFS_IMPL_rename_to_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_rename_to_t *params = (FS_rename_to_t *)job->params;
	char *path = (char *)&params->path;
	char *new_path = (char *)&params->new_path;

	int fs_err = rename(path, new_path);

	if (fs_err == 0) {
		params->result = LLFS_OK;
	} else {
		params->result = LLFS_NOK;
	}

	VEEPORT_LOGGER_LOG_DBG("rename: old name %s, new name %s (status %d err %d errno %d)", path, new_path,
	                       params->result, fs_err, errno);
}

void LLFS_IMPL_get_length_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path64_operation_t *params = (FS_path64_operation_t *)job->params;
	char *path = (char *)&params->path;

	params->result = LLFS_NOK; // error by default

	struct stat buffer;
	int fs_err = stat(path, &buffer);
	if (fs_err == 0) {
		params->result = buffer.st_size;
	}

	VEEPORT_LOGGER_LOG_DBG("length of %s : %lld (err %d errno \"%s\")", path, params->result, fs_err, strerror(errno));
}

void LLFS_IMPL_exist_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path_operation_t *params = (FS_path_operation_t *)job->params;
	char *path = (char *)&params->path;

	struct stat buffer;
	int fs_err = stat(path, &buffer);

	if (fs_err == 0) {
		params->result = LLFS_OK;
	} else {
		params->result = LLFS_NOK;
	}

	VEEPORT_LOGGER_LOG_DBG("exist file %s : %d (err %d errno \"%s\")", path, params->result, fs_err, strerror(errno));
}

void LLFS_IMPL_get_space_size_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_get_space_size *params = (FS_get_space_size *)job->params;
	char *path = (char *)&params->path;
	int32_t space_type = params->space_type;

	params->result = LLFS_NOK; //error by default

	struct statvfs buffer;
	if (statvfs(path, &buffer) >= 0) {
		/* f_blocks, f_bfree and f_bavail are defined in terms of f_frsize */
		jlong scale_factor = (jlong)buffer.f_frsize;

		switch (space_type) {
		case LLFS_FREE_SPACE:
			params->result = ((unsigned long)buffer.f_bfree * scale_factor);
			break;
		case LLFS_TOTAL_SPACE:
			params->result = ((unsigned long)buffer.f_blocks * scale_factor);
			break;
		case LLFS_USABLE_SPACE:
			params->result = ((unsigned long)buffer.f_bavail * scale_factor);
			break;
		}
	}

	VEEPORT_LOGGER_LOG_DBG("get space %d size on %s: %lld", space_type, path, (long long)params->result);
}

void LLFS_IMPL_make_directory_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path_operation_t *params = (FS_path_operation_t *)job->params;
	char *path = (char *)&params->path;

	int fs_err = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
	if (fs_err == 0) {
		params->result = LLFS_OK;
	} else {
		params->result = LLFS_NOK;
	}

	VEEPORT_LOGGER_LOG_DBG("mkdir %s (status %d err %d errno \"%s\")", path, params->result, fs_err, strerror(errno));
}

void LLFS_IMPL_is_hidden_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path_operation_t *params = (FS_path_operation_t *)job->params;
	char *path = (char *)&params->path;

	if (path[0] == '.') {
		params->result = LLFS_OK;
	} else {
		params->result = LLFS_NOK;
	}

	VEEPORT_LOGGER_LOG_DBG("is hidden %s (status %d)", path, params->result);
}

void LLFS_IMPL_is_directory_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path_operation_t *params = (FS_path_operation_t *)job->params;
	char *path = (char *)&params->path;
	struct stat buffer;

	int fs_err = stat(path, &buffer);
	if (fs_err == 0 && S_ISDIR(buffer.st_mode)) {
		params->result = LLFS_OK;
	} else {
		params->result = LLFS_NOK;
	}

	VEEPORT_LOGGER_LOG_DBG("is directory %s (status %d err %d errno \"%s\")", path, params->result, fs_err,
	                       strerror(errno));
}

void LLFS_IMPL_is_file_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path_operation_t *params = (FS_path_operation_t *)job->params;
	char *path = (char *)&params->path;
	struct stat buffer;

	int fs_err = stat(path, &buffer);
	if (fs_err == 0 && !S_ISDIR(buffer.st_mode)) {
		params->result = LLFS_OK;
	} else {
		params->result = LLFS_NOK;
	}

	VEEPORT_LOGGER_LOG_DBG("is file %s (status %d err %d errno \"%s\")", path, params->result, fs_err, strerror(errno));
}

void LLFS_IMPL_set_last_modified_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_last_modified_t *params = (FS_last_modified_t *)job->params;
	char *path = (char *)&params->path;
	LLFS_date_t *new_date = &params->date;

	struct stat buffer;
	int fs_err;
	struct tm date;
	struct utimbuf timebuffer;
	time_t time;

	params->result = LLFS_NOK; // error by default

	fs_err = stat(path, &buffer);
	if (fs_err == 0) {
		date.tm_sec = new_date->second;
		date.tm_min = new_date->minute;
		date.tm_hour = new_date->hour;
		date.tm_mday = new_date->day;
		date.tm_mon = new_date->month;
		date.tm_year = new_date->year - 1900;
		date.tm_isdst = -1;

		//convert date to seconds
		time = mktime(&date);
		if (time != -1) {
			timebuffer.actime = buffer.st_atime;
			timebuffer.modtime = time;
			//change the file modification time
			fs_err = utime(path, &timebuffer);
			if (fs_err == 0) {
				//success
				params->result = LLFS_OK;
			}
		}
	}

	VEEPORT_LOGGER_LOG_DBG("set last modified date on %s (status %d)", path, params->result);
}

void LLFS_IMPL_delete_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_path_operation_t *params = (FS_path_operation_t *)job->params;
	char *path = (char *)&params->path;

	if (unlink(path) == 0 || rmdir(path) == 0) {
		params->result = LLFS_OK;
	} else {
		params->result = LLFS_NOK;
	}

	VEEPORT_LOGGER_LOG_DBG("delete %s (status %d, errno: \"%s\")", path, params->result, strerror(errno));
}

void LLFS_IMPL_is_accessible_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_is_accessible_t *params = (FS_is_accessible_t *)job->params;
	char *path = (char *)&params->path;
	int32_t checked_access = params->access;

	params->result = LLFS_NOK; // error by default

	int mode; // mode for POSIX access

	switch (checked_access) {
	case LLFS_ACCESS_READ:
		mode = R_OK;
		break;

	case LLFS_ACCESS_WRITE:
		mode = W_OK;
		break;

	case LLFS_ACCESS_EXECUTE:
		mode = X_OK;
		break;

	default:
		// Unknown access
		return;
	}

	if (access(path, mode) == 0) {
		params->result = LLFS_OK;
	}

	VEEPORT_LOGGER_LOG_DBG("is accessible %s access %d (status %d)", path, checked_access, params->result);
}

void LLFS_IMPL_set_permission_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_set_permission_t *params = (FS_set_permission_t *)job->params;
	char *path = (char *)&params->path;
	int32_t modified_access = params->access;
	int32_t enable = params->enable;
	int32_t owner = params->owner;

	mode_t perms;
	struct stat buffer;

	params->result = LLFS_NOK; // error by default

	if (stat(path, &buffer) == 0) {
		switch (modified_access) {
		case LLFS_ACCESS_READ:
			if (owner == LLFS_PERMISSION_OWNER_ONLY) {
				perms = S_IRUSR;
			} else {
				perms = (S_IRUSR | S_IRGRP | S_IROTH);
			}
			break;

		case LLFS_ACCESS_WRITE:
			if (owner == LLFS_PERMISSION_OWNER_ONLY) {
				perms = S_IWUSR;
			} else {
				perms = (S_IWUSR | S_IWGRP | S_IWOTH);
			}
			break;

		case LLFS_ACCESS_EXECUTE:
			if (owner == LLFS_PERMISSION_OWNER_ONLY) {
				perms = S_IXUSR;
			} else {
				perms = (S_IXUSR | S_IXGRP | S_IXOTH);
			}
			break;

		default:
			// Unknown access
			return;
		}

		if (enable == LLFS_PERMISSION_ENABLE) {
			perms = buffer.st_mode | perms;
		} else {
			perms = buffer.st_mode & ~perms;
		}

		if (chmod(path, perms) == 0) {
			// OK
			params->result = LLFS_OK;
		}
		// else error chmod
	}

	VEEPORT_LOGGER_LOG_DBG("set permission %s access %d enable %d owner %d (status %d)", path, modified_access, enable,
	                       owner, params->result);
}

void LLFS_File_IMPL_open_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_open_t *params = (FS_open_t *)job->params;
	char *path = (char *)&params->path;
	uint8_t mode = params->mode;

	params->result = LLFS_NOK; // error by default
	params->error_code = 0;

	char *open_mode;
	int fd_mode;
	switch (mode) {
	case LLFS_FILE_MODE_READ:
		fd_mode = O_RDONLY;
		open_mode = "r";
		break;

	case LLFS_FILE_MODE_WRITE:
		fd_mode = O_WRONLY | O_CREAT | O_TRUNC;
		open_mode = "w";
		break;

	case LLFS_FILE_MODE_APPEND:
		fd_mode = O_WRONLY | O_CREAT | O_APPEND;
		open_mode = "a";
		break;

	case LLFS_FILE_MODE_READ_WRITE:
	case LLFS_FILE_MODE_READ_WRITE_DATA_SYNC:
	case LLFS_FILE_MODE_READ_WRITE_SYNC:
		fd_mode = O_RDWR | O_CREAT;
		open_mode = "r+";
		if (mode == LLFS_FILE_MODE_READ_WRITE_DATA_SYNC) {
			fd_mode |= O_DSYNC;
		} else if (mode == LLFS_FILE_MODE_READ_WRITE_SYNC) {
			fd_mode |= O_SYNC;
		}
		break;
	default:
		params->error_code = EINVAL;
		return;
	}

	int fd = open(path, fd_mode, LLFS_NORMAL_PERMISSIONS);
	if (fd == -1) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		// check if file is a file not a directory
		struct stat s;
		int fstat_err = fstat(fd, &s);
		if (fstat_err != -1) {
			if (S_ISDIR(s.st_mode)) {
				params->error_code = EISDIR;
				close(fd);
			} else {
#if FS_BUFFERING_ENABLED == 0
				//No buffering mode
				//data is transfered to the destination file as soon as it is written.
				int buffering_mode = _IONBF;
				size_t buffer_size = 0;
#else
				// input and output will be fully buffered
				int buffering_mode = _IOFBF;
				size_t buffer_size = FS_BUFFER_SIZE;
#endif

				FILE *file = fdopen(fd, open_mode);
				if (file == NULL || setvbuf(file, NULL, buffering_mode, buffer_size) != 0) {
					FS_SET_ERRNO_ERROR(params);
				} else {
					params->result = (int)file; // no error
				}
			}
		} else {
			FS_SET_ERRNO_ERROR(params);
			close(fd);
		}
	}

	VEEPORT_LOGGER_LOG_DBG("open %s mode %d (status %d errno \"%s\")", path, mode, params->result,
	                       strerror(errno));
}

void LLFS_File_IMPL_write_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_write_read_t *params = (FS_write_read_t *)job->params;
	FILE *file = (FILE *)params->file_id;
	uint8_t *data = params->data;
	int32_t length = params->length;

	struct stat stat_buffer;
	int fd = fileno(file);
	int fstat_err = fstat(fd, &stat_buffer);
	if (fstat_err != 0) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		switch (stat_buffer.st_mode & S_IFMT) {
		case S_IFREG: // regular files
			LLFS_File_IMPL_buffered_write(file, data, length, params);
			break;
		case S_IFCHR:
		default: // other type of files
			LLFS_File_IMPL_regular_write(fd, data, length, params);
			break;
		}
	}

	VEEPORT_LOGGER_LOG_DBG("write file content %p - %d bytes to write (status %d errno \"%s\")", (void *)file, length,
	                       params->result, strerror(errno));
}

/**
 * Do a buffered write from the data buffer into file.
 * this method is suitable for regular files.
 */
static void LLFS_File_IMPL_buffered_write(FILE *file, uint8_t *data, int32_t length, FS_write_read_t *params) {
	size_t written_count = fwrite(data, 1, length, file);
	if (written_count == 0 && length > 0) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		params->result = written_count;
	}
}

/**
 * do a standard write from the data buffer into the file.
 */
static void LLFS_File_IMPL_regular_write(int file_desc, uint8_t *data, int32_t length, FS_write_read_t *params) {
	ssize_t written_count = write(file_desc, data, length);
	if (written_count < 0 || (written_count == 0 && length > 0)) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		params->result = written_count;
	}
}

void LLFS_File_IMPL_read_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_write_read_t *params = (FS_write_read_t *)job->params;
	FILE *file = (FILE *)params->file_id;
	uint8_t *data = params->data;
	int32_t length = params->length;

	struct stat stat_buffer;
	int fd = fileno(file);
	int fstat_err = fstat(fd, &stat_buffer);
	if (fstat_err != 0) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		switch (stat_buffer.st_mode & S_IFMT) {
		case S_IFREG: // regular files
			LLFS_File_IMPL_buffered_read(file, data, length, params);
			break;
		case S_IFCHR:
		default: // other type of files
			LLFS_File_IMPL_regular_read(fd, data, length, params);
			break;
		}
	}

	VEEPORT_LOGGER_LOG_DBG("read file content %p - %d bytes to read (status %d errno \"%s\")", (void *)file, length,
	                       params->result, strerror(errno));
}

/**
 * Do a buffered read from the file into data buffer.
 * this method is suitable for regular files.
 */
static void LLFS_File_IMPL_buffered_read(FILE *file, uint8_t *data, int32_t length, FS_write_read_t *params) {
	size_t read_count = fread(data, 1, length, file);
	if (read_count < 1) {
		if (feof(file)) {
			clearerr(file);
			params->result = LLFS_EOF; // EOF
		} else {
			FS_SET_ERRNO_ERROR(params);
		}
	} else {
		params->result = read_count;
	}
}

/**
 * do a standard read from a file into data buffer.
 */
static void LLFS_File_IMPL_regular_read(int file_desc, uint8_t *data, int32_t length, FS_write_read_t *params) {
	ssize_t read_count = read(file_desc, data, length);
	if (read_count != -1) {
		if (read_count == 0) {
			params->result = LLFS_EOF; // EOF
		} else {
			params->result = read_count;
		}
	} else {
		FS_SET_ERRNO_ERROR(params);
	}
}

void LLFS_File_IMPL_close_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_close_t *params = (FS_close_t *)job->params;
	FILE *file = (FILE *)params->file_id;

	int fs_err = fclose(file);
	if (fs_err != 0) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		params->result = LLFS_OK;
	}

	VEEPORT_LOGGER_LOG_DBG("close file %p (status %d errno \"%s\")", (void *)params->file_id, params->result,
	                       strerror(errno));
}

void LLFS_File_IMPL_seek_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_seek_t *params = (FS_seek_t *)job->params;
	FILE *file = (FILE *)params->file_id;
	int64_t n = params->n;
	int seek_err;

#if (_FILE_OFFSET_BITS == 64)
	off_t pos = (off_t)n;
	// Depending on the libc implementation, fseeko will only accept values <= FS_LARGE_FILE_MAX_OFFSET
	if (pos > (off_t)(FS_LARGE_FILE_MAX_OFFSET)) {
		VEEPORT_LOGGER_LOG_DBG("Saturate offset %lld to %lld (FS_LARGE_FILE_MAX_OFFSET)", pos,
		                       FS_LARGE_FILE_MAX_OFFSET);
		pos = (off_t)(FS_LARGE_FILE_MAX_OFFSET);
	}
	seek_err = fseeko(file, pos, SEEK_SET);
#else
	// Convert given offset in a type accepted by fseek
	long pos = (long)n;

	// Check if the conversion from long long int to long is correct
	if (pos != n) {
		// An overflow occurs, saturate the value
		pos = INT32_MAX;
	}

	seek_err = fseek(file, pos, SEEK_SET);
#endif

	if (seek_err != -1) {
		// Seek done
		params->result = LLFS_OK;

#if (_FILE_OFFSET_BITS == 64)
		VEEPORT_LOGGER_LOG_DBG("file %p seek to n %lld", (void *)file, (long long)pos);
#else
		VEEPORT_LOGGER_LOG_DBG("file %p seek to n %ld", (void *)file, (long)pos);
#endif

		return;
	}

	// Error occurred
	FS_SET_ERRNO_ERROR(params);

#if (_FILE_OFFSET_BITS == 64)
	VEEPORT_LOGGER_LOG_DBG("error seek to %lld on %p (status %d errno \"%s\")", (long long)pos, (void *)file,
	                       params->result, strerror(errno));
#else
	VEEPORT_LOGGER_LOG_DBG("error seek to %ld on %p (status %d errno \"%s\")", (long)pos, (void *)file,
	                       params->result, strerror(errno));
#endif
}

void LLFS_File_IMPL_get_file_pointer_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_getfp_t *params = (FS_getfp_t *)job->params;
	FILE *file = (FILE *)params->file_id;
	params->error_code = 0;

	//Get current file position
#if (_FILE_OFFSET_BITS == 64)
	params->result = ftello(file);
#else
	params->result = ftell(file);
#endif

	if (params->result < 0) {
		// Error occurred
		FS_SET_ERRNO_ERROR(params);
	}

	VEEPORT_LOGGER_LOG_DBG("get file pointer on %p (status %lld errno \"%s\")", (void *)file,
	                       (long long)params->result, strerror(errno));
}

void LLFS_File_IMPL_set_length_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_set_length_t *params = (FS_set_length_t *)job->params;
	FILE *file = (FILE *)params->file_id;
	params->result = LLFS_NOK; // error by default
	params->error_code = 0;

	int fs_err = ftruncate(fileno(file), params->length);
	if (fs_err != 0) {
		FS_SET_ERRNO_ERROR(params);
	} else {
#if (_FILE_OFFSET_BITS == 64)
		if (params->length < ftello(file)) {
			fseek(file, params->length, SEEK_SET);
		}
#else
		if (params->length < ftell(file)) {
			fseek(file, params->length, SEEK_SET);
		}
#endif
		params->result = LLFS_OK;
	}

	VEEPORT_LOGGER_LOG_DBG("set length of %p to %lld (err %d errno \"%s\")", (void *)file, (long long)params->length,
	                       fs_err, strerror(errno));
}

void LLFS_File_IMPL_get_length_with_fd_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_get_length_with_fd_t *params = (FS_get_length_with_fd_t *)job->params;
	FILE *file = (FILE *)params->file_id;
	params->result = LLFS_NOK; // error by default
	params->error_code = 0;

	int fs_err;

#if (_FILE_OFFSET_BITS == 64)
	off_t pos = ftello(file);
	fs_err = fseeko(file, 0, SEEK_END);
	params->result = ftello(file);
	fseeko(file, pos, SEEK_SET);
#else
	long pos = ftell(file);
	fs_err = fseek(file, 0, SEEK_END);
	params->result = ftell(file);
	fseek(file, pos, SEEK_SET);
#endif

	if (fs_err != 0) {
		FS_SET_ERRNO_ERROR(params);
	}

	VEEPORT_LOGGER_LOG_DBG("length of %p: %lld (err %d errno \"%s\")", (void *)file, (long long)params->result, fs_err,
	                       strerror(errno));
}

void LLFS_File_IMPL_available_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_available_t *params = (FS_available_t *)job->params;
	FILE *file = (FILE *)(params->file_id);

	params->result = LLFS_NOK; // error by default

	int fd = fileno(file);
	struct stat stat_buffer;
	int stat_err = fstat(fd, &stat_buffer);
	if (stat_err != 0) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		switch (stat_buffer.st_mode & S_IFMT) {
		case S_IFCHR:
			LLFS_File_IMPL_get_available_data_IFCHR(fd, params);
			break;
		default:
			LLFS_File_IMPL_gett_available_data(file, stat_buffer.st_size, params);
			break;
		}
	}

	VEEPORT_LOGGER_LOG_DBG("available %d bytes on %p (errno \"%s\")", params->result, (void *)file, strerror(errno));
}

static void LLFS_File_IMPL_get_available_data_IFCHR(int file_desc, FS_available_t *params) {
	int nread = 0;
	int rc = ioctl(file_desc, FIONREAD, &nread);
	if (rc < 0) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		params->result = nread;
	}
}

static void LLFS_File_IMPL_gett_available_data(FILE *file, uint64_t file_size, FS_available_t *params) {
	if (file_size == 0) {
		params->result = 0;
	} else {
		// Get current position
#if (_FILE_OFFSET_BITS == 64)
		off_t current_position = ftello(file);
#else
		long current_position = ftell(file);
#endif
		if (current_position != -1) {
			int64_t available = file_size - current_position;
			if (available < 0) {
				available = 0;
			}
			if ((int)available != available) {
				//overflow when casting on int: return max value
				params->result = INT32_MAX;
			} else {
				params->result = (int)available;
			}
		} else {
			// error during ftell
			FS_SET_ERRNO_ERROR(params);
		}
	}
}

void LLFS_File_IMPL_flush_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	FS_flush_t *params = (FS_flush_t *)job->params;
	FILE *file = (FILE *)params->file_id;

	int flush_res = fflush(file);
	if (flush_res != 0) {
		FS_SET_ERRNO_ERROR(params);
	} else {
		params->result = LLFS_OK;
	}

	VEEPORT_LOGGER_LOG_DBG("flush file %p (status %d errno \"%s\")", (void *)file, params->result, strerror(errno));
}

int32_t LLFS_copy_path_param(uint8_t *path, uint8_t *path_param) {
	int32_t path_length = SNI_getArrayLength(path);
	if (path_length > FS_PATH_LENGTH) {
		// Path too long for the buffer
		return LLFS_NOK;
	}
	// cppcheck-suppress misra-c2012-17.7 // Return value does not require checking.
	memcpy(path_param, path, path_length);
	return LLFS_OK;
}

void LLFS_throw_job_error(int32_t fd_errno) {
	if (0 != fd_errno) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLFS_NOK, "errno %d: %s", fd_errno, strerror(fd_errno));
	} else {
		VEEPORT_ERRORS_throw_caught_exception(LLFS_NOK);
	}
}

#ifdef __cplusplus
}
#endif
