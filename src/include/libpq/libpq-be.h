/*-------------------------------------------------------------------------
 *
 * libpq_be.h
 *	  This file contains definitions for structures and externs used
 *	  by the postmaster during client authentication.
 *
 *	  Note that this is backend-internal and is NOT exported to clients.
 *	  Structs that need to be client-visible are in pqcomm.h.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/libpq/libpq-be.h,v 1.71 2009/06/11 14:49:11 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#ifndef LIBPQ_BE_H
#define LIBPQ_BE_H

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef ENABLE_GSS
#if defined(HAVE_GSSAPI_H)
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif   /* HAVE_GSSAPI_H */
/*
 * GSSAPI brings in headers that set a lot of things in the global namespace on win32,
 * that doesn't match the msvc build. It gives a bunch of compiler warnings that we ignore,
 * but also defines a symbol that simply does not exist. Undefine it again.
 */
#ifdef WIN32_ONLY_COMPILER
#undef HAVE_GETADDRINFO
#endif
#endif   /* ENABLE_GSS */

#ifdef ENABLE_SSPI
#define SECURITY_WIN32
#if defined(WIN32) && !defined(WIN32_ONLY_COMPILER)
#include <ntsecapi.h>
#endif
#include <security.h>
#undef SECURITY_WIN32

#ifndef ENABLE_GSS
/*
 * Define a fake structure compatible with GSSAPI on Unix.
 */
typedef struct
{
	void	   *value;
	int			length;
} gss_buffer_desc;
#endif
#endif   /* ENABLE_SSPI */

#include "libpq/hba.h"
#include "libpq/pqcomm.h"
#include "utils/timestamp.h"


typedef enum CAC_state
{
	CAC_OK, CAC_STARTUP, CAC_SHUTDOWN, CAC_RECOVERY, CAC_TOOMANY,
	CAC_WAITBACKUP
} CAC_state;


/*
 * GSSAPI specific state information
 */
#if defined(ENABLE_GSS) | defined(ENABLE_SSPI)
typedef struct
{
	gss_buffer_desc outbuf;		/* GSSAPI output token buffer */
#ifdef ENABLE_GSS
	gss_cred_id_t cred;			/* GSSAPI connection cred's */
	gss_ctx_id_t ctx;			/* GSSAPI connection context */
	gss_name_t	name;			/* GSSAPI client name */
#endif
} pg_gssinfo;
#endif

/*
 * @struct Port
 * 该结构体用于存储与客户端连接相关的所有状态信息，在后端运行之前的通信过程中使用。
 * 它被存储在动态分配的内存中，后端运行时仍然可用。
 * 结构体中的指针成员指向的数据也必须是动态分配的，或者在 TopMemoryContext 中使用 palloc 分配，
 * 以确保在 PostgresMain 执行期间数据不会丢失。
 * 
 */

typedef struct Port
{
    int         sock;           /* 连接的文件描述符 */
    ProtocolVersion proto;      /* 前端/后端协议版本 */
    SockAddr    laddr;          /* 本地地址（Postmaster） */
    SockAddr    raddr;          /* 远程地址（客户端） */
    char       *remote_host;    /* 远程主机的名称（或 IP 地址） */
    char       *remote_port;    /* 远程端口的文本表示 */
    CAC_state   canAcceptConnections; /* Postmaster 连接状态 */

	/*
	 * Information that needs to be saved from the startup packet and passed
	 * into backend execution.	"char *" fields are NULL if not set.
	 * guc_options points to a List of alternating option names and values.
	 */
    char       *database_name;  /* 数据库名称 */
    char       *user_name;      /* 用户名称 */
    char       *cmdline_options; /* 命令行选项 */
    List       *guc_options;    /* GUC 选项列表 */

	/*
	 * Information that needs to be held during the authentication cycle.
	 */
    HbaLine    *hba;            /* HBA 配置行 */
    char        md5Salt[4];     /* 密码盐 */

	/*
	 * Information that really has no business at all being in struct Port,
	 * but since it gets used by elog.c in the same way as database_name and
	 * other members of this struct, we may as well keep it here.
	 */
	TimestampTz SessionStartTime;		/* 后端启动时间 */

	/*
	 * TCP keepalive settings.
	 *
	 * default values are 0 if AF_UNIX or not yet known; current values are 0
	 * if AF_UNIX or using the default. Also, -1 in a default value means we
	 * were unable to find out the default (getsockopt failed).
	 */
    int         default_keepalives_idle;    /* 默认的 TCP 保活空闲时间 */
    int         default_keepalives_interval; /* 默认的 TCP 保活间隔时间 */
    int         default_keepalives_count;   /* 默认的 TCP 保活重试次数 */
    int         keepalives_idle;            /* 当前的 TCP 保活空闲时间 */
    int         keepalives_interval;        /* 当前的 TCP 保活间隔时间 */
    int         keepalives_count;           /* 当前的 TCP 保活重试次数 */

#if defined(ENABLE_GSS) || defined(ENABLE_SSPI)

	/*
	 * If GSSAPI is supported, store GSSAPI information. Oterwise, store a
	 * NULL pointer to make sure offsets in the struct remain the same.
	 */
	pg_gssinfo *gss;
#else
	void	   *gss;
#endif

	/*
	 * SSL structures (keep these last so that USE_SSL doesn't affect
	 * locations of other fields)
	 */
#ifdef USE_SSL
	SSL		   *ssl;
	X509	   *peer;
	char		peer_dn[128 + 1];
	char		peer_cn[SM_USER + 1];
	unsigned long count;
#endif
} Port;


extern ProtocolVersion FrontendProtocol;

/* TCP keepalives configuration. These are no-ops on an AF_UNIX socket. */

extern int	pq_getkeepalivesidle(Port *port);
extern int	pq_getkeepalivesinterval(Port *port);
extern int	pq_getkeepalivescount(Port *port);

extern int	pq_setkeepalivesidle(int idle, Port *port);
extern int	pq_setkeepalivesinterval(int interval, Port *port);
extern int	pq_setkeepalivescount(int count, Port *port);

#endif   /* LIBPQ_BE_H */
