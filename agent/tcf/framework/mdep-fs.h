/*******************************************************************************
 * Copyright (c) 2013 Xilinx, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Xilinx - initial API and implementation
 *******************************************************************************/

/*
 * Machine and OS dependent definitions for file system.
 */

#ifndef D_mdep_fs
#define D_mdep_fs

#if (defined(_WIN32) && !defined(__CYGWIN__)) || defined(__MINGW32__)

#include <direct.h>

/* UTF-8 support */
struct utf8_stat {
    dev_t      st_dev;
    ino_t      st_ino;
    unsigned short st_mode;
    short      st_nlink;
    short      st_uid;
    short      st_gid;
    dev_t      st_rdev;
    int64_t    st_size;
    int64_t    st_atime;
    int64_t    st_mtime;
    int64_t    st_ctime;
};
#undef stat
#undef lstat
#undef fstat
#undef open
#undef chmod
#undef remove
#undef rmdir
#undef mkdir
#undef rename
#define stat   utf8_stat
#define lstat  utf8_stat
#define fstat  utf8_fstat
#define open   utf8_open
#define chmod  utf8_chmod
#define remove utf8_remove
#define rmdir  utf8_rmdir
#define mkdir  utf8_mkdir
#define rename utf8_rename
extern int utf8_stat(const char * name, struct utf8_stat * buf);
extern int utf8_fstat(int fd, struct utf8_stat * buf);
extern int utf8_open(const char * name, int flags, int perms);
extern int utf8_chmod(const char * name, int mode);
extern int utf8_remove(const char * path);
extern int utf8_rmdir(const char * path);
extern int utf8_mkdir(const char * path, int mode);
extern int utf8_rename(const char * path1, const char * path2);

/*
 * readdir() emulation with UTF-8 support
 */
struct utf8_dirent {
  char d_name[FILE_PATH_SIZE];
  int64_t d_size;
  time_t d_atime;
  time_t d_ctime;
  time_t d_wtime;
};

struct UTF8_DIR {
  intptr_t hdl;
  struct _wfinddatai64_t blk;
  struct utf8_dirent de;
  wchar_t * path;
};

typedef struct UTF8_DIR UTF8_DIR;

#define DIR UTF8_DIR
#define dirent   utf8_dirent
#define opendir  utf8_opendir
#define closedir utf8_closedir
#define readdir  utf8_readdir

extern DIR * utf8_opendir(const char * path);
extern int utf8_closedir(DIR * dir);
extern struct utf8_dirent * readdir(DIR * dir);

#else

#include <dirent.h>

#endif

#endif /* D_mdep_fs */
