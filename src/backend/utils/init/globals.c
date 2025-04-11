/*-------------------------------------------------------------------------
 *
 * globals.c
 *	  global variable declarations
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/utils/init/globals.c,v 1.108 2009/05/05 19:59:00 tgl Exp $
 *
 * NOTES
 *	  Globals used all over the place should be declared here and not
 *	  in other modules.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "libpq/pqcomm.h"
#include "miscadmin.h"
#include "storage/backendid.h"


ProtocolVersion FrontendProtocol = PG_PROTOCOL_LATEST;  // 前端协议版本，默认为最新版本

volatile bool InterruptPending = false;                // 是否有中断请求待处理
volatile bool QueryCancelPending = false;              // 是否有查询取消请求待处理
volatile bool ProcDiePending = false;                  // 是否有进程终止请求待处理
volatile bool ImmediateInterruptOK = false;            // 是否允许立即处理中断
volatile uint32 InterruptHoldoffCount = 0;             // 中断延迟计数，用于控制中断处理的时机
volatile uint32 CritSectionCount = 0;                  // 临界区计数，用于控制临界区的进入和退出

int			MyProcPid;                                // 当前进程的 PID
pg_time_t	MyStartTime;                              // 当前进程的启动时间
struct Port *MyProcPort;                              // 当前进程的端口信息
long		MyCancelKey;                              // 当前进程的取消键，用于取消操作
int			MyPMChildSlot;                           // 当前进程在 postmaster 中的子进程槽位

/*
 * DataDir is the absolute path to the top level of the PGDATA directory tree.
 * Except during early startup, this is also the server's working directory;
 * most code therefore can simply use relative paths and not reference DataDir
 * explicitly.
 */
char	   *DataDir = NULL;   // PostgreSQL 数据目录的绝对路径，默认为 NULL

char		OutputFileName[MAXPGPATH];	/* debugging output file */ // 调试输出文件的路径

char		my_exec_path[MAXPGPATH];	/* full path to my executable */  // 当前可执行文件的完整路径
char		pkglib_path[MAXPGPATH];		/* full path to lib directory */  // PostgreSQL 库目录的完整路径

#ifdef EXEC_BACKEND
char		postgres_exec_path[MAXPGPATH];		/* full path to backend */

/* note: currently this is not valid in backend processes */
#endif

BackendId	MyBackendId = InvalidBackendId;

Oid			MyDatabaseId = InvalidOid;

Oid			MyDatabaseTableSpace = InvalidOid;

/*
 * DatabasePath is the path (relative to DataDir) of my database's
 * primary directory, ie, its directory in the default tablespace.
 */
char	   *DatabasePath = NULL;

pid_t		PostmasterPid = 0;

/*
 * IsPostmasterEnvironment is true in a postmaster process and any postmaster
 * child process; it is false in a standalone process (bootstrap or
 * standalone backend).  IsUnderPostmaster is true in postmaster child
 * processes.  Note that "child process" includes all children, not only
 * regular backends.  These should be set correctly as early as possible
 * in the execution of a process, so that error handling will do the right
 * things if an error should occur during process initialization.
 *
 * These are initialized for the bootstrap/standalone case.
 */
bool		IsPostmasterEnvironment = false;  // 标识当前进程是否在 postmaster 环境中运行
bool		IsUnderPostmaster = false;        // 标识当前进程是否为 postmaster 的子进程

bool		ExitOnAnyError = false;           // 是否在任何错误发生时立即退出

int			DateStyle = USE_ISO_DATES;        // 日期显示风格，默认为 ISO 格式
int			DateOrder = DATEORDER_MDY;        // 日期顺序，默认为月-日-年
int			IntervalStyle = INTSTYLE_POSTGRES; // 时间间隔显示风格，默认为 PostgreSQL 风格
bool		HasCTZSet = false;                // 是否设置了客户端时区
int			CTimeZone = 0;                    // 客户端时区偏移量（秒）

bool		enableFsync = true;               // 是否启用 fsync 强制刷新磁盘
bool		allowSystemTableMods = false;     // 是否允许修改系统表
int			work_mem = 1024;                  // 每个查询操作可用的内存大小（KB）
int			maintenance_work_mem = 16384;     // 维护操作（如 VACUUM）可用的内存大小（KB）

/*
 * Primary determinants of sizes of shared-memory structures.  MaxBackends is
 * MaxConnections + autovacuum_max_workers (it is computed by the GUC assign
 * hook):
 */
int			NBuffers = 1000;              // 共享内存中缓冲区的数量
int			MaxBackends = 100;            // 最大后台进程数（包括连接和自动清理进程）
int			MaxConnections = 90;          // 最大客户端连接数

int			VacuumCostPageHit = 1;        // VACUUM 操作中访问已缓存页面的成本
int			VacuumCostPageMiss = 10;      // VACUUM 操作中访问未缓存页面的成本
int			VacuumCostPageDirty = 20;     // VACUUM 操作中写入脏页的成本
int			VacuumCostLimit = 200;        // VACUUM 操作的成本限制
int			VacuumCostDelay = 0;          // VACUUM 操作的成本延迟（毫秒）

int			VacuumCostBalance = 0;        // VACUUM 操作的成本余额（工作状态）
bool		VacuumCostActive = false;     // 是否启用 VACUUM 成本控制

int			GinFuzzySearchLimit = 0;      // GIN 索引模糊搜索的限制值
