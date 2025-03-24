/*-------------------------------------------------------------------------
 *
 * main.c
 *	  Stub main() routine for the postgres executable.
 *
 * This does some essential startup tasks for any incarnation of postgres
 * (postmaster, standalone backend, or standalone bootstrap mode) and then
 * dispatches to the proper FooMain() routine for the incarnation.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/main/main.c,v 1.112 2009/01/01 17:23:43 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <pwd.h>
#include <unistd.h>

#if defined(__alpha) && defined(__osf__)		/* no __alpha__ ? */
#include <sys/sysinfo.h>
#include "machine/hal_sysinfo.h"
#define ASSEMBLER
#include <sys/proc.h>
#undef ASSEMBLER
#endif

#if defined(__NetBSD__)
#include <sys/param.h>
#endif

#include "bootstrap/bootstrap.h"
#include "postmaster/postmaster.h"
#include "tcop/tcopprot.h"
#include "utils/help_config.h"
#include "utils/pg_locale.h"
#include "utils/ps_status.h"
#ifdef WIN32
#include "libpq/pqsignal.h"
#endif


const char *progname;


static void startup_hacks(const char *progname);
static void help(const char *progname);
static void check_root(const char *progname);
static char *get_current_username(const char *progname);



int
main(int argc, char *argv[])
{
	// 从程序的完整路径中提取出可执行文件的名称，实例多为"postgres"。【const char *】意味着这是个只读字符串。
	progname = get_progname(argv[0]);

	/*
	 * Platform-specific startup hacks
	 * 根据当前运行的操作系统或硬件平台，执行一些必要的初始化或配置工作。
	 * 由于我们目前使用linux平台，该函数并不涉及Linux系统的配置工作，此步骤可以跳过。
	 */
	startup_hacks(progname);

	/*
	 * Remember the physical location of the initially given argv[] array for
	 * possible use by ps display.	On some platforms, the argv[] storage must
	 * be overwritten in order to set the process title for ps. In such cases
	 * save_ps_display_args makes and returns a new copy of the argv[] array.
	 *
	 * save_ps_display_args may also move the environment strings to make
	 * extra room. Therefore this should be done as early as possible during
	 * startup, to avoid entanglements with code that might save a getenv()
	 * result pointer.
	 * 一句话总结：备份命令行参数和环境变量
	 */
	argv = save_ps_display_args(argc, argv);

	/*
	 * Set up locale information from environment.	Note that LC_CTYPE and
	 * LC_COLLATE will be overridden later from pg_control if we are in an
	 * already-initialized database.  We set them here so that they will be
	 * available to fill pg_control during initdb.	LC_MESSAGES will get set
	 * later during GUC option processing, but we set it here to allow startup
	 * error messages to be localized.
	 * 一句话总结：通过 argv[0] 获取程序的路径，并结合 PG_TEXTDOMAIN("postgres") 设置语言环境和文本域，确保 PostgreSQL 能够正确支持多语言和本地化功能
	 */

	set_pglocale_pgservice(argv[0], PG_TEXTDOMAIN("postgres"));

#ifdef WIN32

	/*
	 * Windows uses codepages rather than the environment, so we work around
	 * that by querying the environment explicitly first for LC_COLLATE and
	 * LC_CTYPE. We have to do this because initdb passes those values in the
	 * environment. If there is nothing there we fall back on the codepage.
	 *  一句话总结：Windows设置语言环境
	 */
	{
		char	   *env_locale;

		if ((env_locale = getenv("LC_COLLATE")) != NULL)
			pg_perm_setlocale(LC_COLLATE, env_locale);
		else
			pg_perm_setlocale(LC_COLLATE, "");

		if ((env_locale = getenv("LC_CTYPE")) != NULL)
			pg_perm_setlocale(LC_CTYPE, env_locale);
		else
			pg_perm_setlocale(LC_CTYPE, "");
	}
#else
	// *  一句话总结：设置语言环境,空字符串表示使用系统默认的语言环境。
	pg_perm_setlocale(LC_COLLATE, "");
	pg_perm_setlocale(LC_CTYPE, "");
#endif

#ifdef LC_MESSAGES
	// 确保能够根据系统配置输出本地化的消息。空字符串表示使用系统默认的语言环境，从而支持多语言功能。
	pg_perm_setlocale(LC_MESSAGES, "");
#endif

	/*
	 * We keep these set to "C" always, except transiently in pg_locale.c; see
	 * that file for explanations.
	 * 确保 PostgreSQL 在处理货币、数字和日期时间时使用统一的、无本地化的格式，从而避免因本地化设置不同而导致的格式不一致问题。
	 */
	pg_perm_setlocale(LC_MONETARY, "C");
	pg_perm_setlocale(LC_NUMERIC, "C");
	pg_perm_setlocale(LC_TIME, "C");

	/*
	 * Now that we have absorbed as much as we wish to from the locale
	 * environment, remove any LC_ALL setting, so that the environment
	 * variables installed by pg_perm_setlocale have force.
	 * LC_ALL的优先级最高，会覆盖其他所有LC_*变量（如LC_CTYPE、LC_COLLATE）和LANG的设置。
	 * 如果 LC_ALL 被设置，它会强制所有语言环境类别使用相同的值。
	 * 通过unsetenv("LC_ALL")删除该变量，避免其后续影响。
	 * 移除LC_ALL后，后续代码（如pg_perm_setlocale）可以通过设置特定的LC_*变量（如LC_COLLATE）调整本地化行为，而不会被LC_ALL覆盖。
	 */
	unsetenv("LC_ALL");

	/*
	 * Catch standard options before doing much else
	 * 处理了两个标准的命令行选项：--help（或 -?）和 --version（或 -V）
	 * 例如：./postgres --version
	 */
	if (argc > 1)
	{
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
		{
			help(progname);
			exit(0);
		}
		if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		{
			puts("postgres (PostgreSQL) " PG_VERSION);
			exit(0);
		}
	}

	/*
	 * Make sure we are not running as root.
	 * 禁止root用户运行此程序。
	 * 1、最小权限原则：如果 PostgreSQL 存在漏洞，攻击者可能利用这些漏洞获取 root 权限，从而完全控制系统。
	 * 2、防止权限滥用：数据库进程可以修改系统关键文件（如 /etc/passwd、/etc/shadow）；数据库进程可以启动或终止其他系统服务。
	 * 3、防止 setuid 漏洞：如果以 setuid 方式运行（即普通用户启动但以 root 权限运行），可能存在以下风险：
				- 恶意代码可能通过 setuid 机制提升权限，获取 root 权限。
				- 即使 PostgreSQL 本身没有漏洞，其他依赖库或插件中的漏洞也可能被利用。
	 */
	check_root(progname);

	/*
	 * Dispatch to one of various subprograms depending on first argument.
	 */

#ifdef EXEC_BACKEND  // 此模式为Windows专用，EXEC_BACKEND 通常用于创建子进程。
	// 只有在定义了 EXEC_BACKEND 并且命令行参数包含 --fork 时，才调用SubPostmasterMain并退出，不执行后续代码
	if (argc > 1 && strncmp(argv[1], "--fork", 6) == 0)
		// 父进程不会使用 --fork 参数，因此不会进入 EXEC_BACKEND 的 exit 逻辑。
		exit(SubPostmasterMain(argc, argv));
#endif

#ifdef WIN32

	/*
	 * Start our win32 signal implementation
	 *
	 * SubPostmasterMain() will do this for itself, but the remaining modes
	 * need it here
	 * 在 Windows 平台上初始化信号处理。
	 * 父进程会执行这段代码，初始化信号处理。
	 */
	pgwin32_signal_initialize();
#endif

	// 启动辅助进程（如 bootstrap 模式），并且不会返回。
	// Bootstrap 模式：用于初始化数据库系统表，通常在数据库初始化（initdb）时使用。
    // 注意，当进入这个if之后，程序可能会已终止或永久阻塞在 AuxiliaryProcessMain 中，永远不会执行最后一行的 exit(PostmasterMain(argc, argv));
	if (argc > 1 && strcmp(argv[1], "--boot") == 0)
		AuxiliaryProcessMain(argc, argv);		/* does not return */

	// 描述配置参数，通常用于调试或获取配置信息。
	// GUC（Grand Unified Configuration）：PostgreSQL 的配置管理系统，用于管理所有运行时参数。
	if (argc > 1 && strcmp(argv[1], "--describe-config") == 0)
		exit(GucInfoMain());

	// 启动单用户模式，通常用于数据库维护或修复。
	if (argc > 1 && strcmp(argv[1], "--single") == 0)
		exit(PostgresMain(argc, argv, get_current_username(progname)));

	exit(PostmasterMain(argc, argv));
}



/*
 * Place platform-specific startup hacks here.	This is the right
 * place to put code that must be executed early in launch of either a
 * postmaster, a standalone backend, or a standalone bootstrap run.
 * Note that this code will NOT be executed when a backend or
 * sub-bootstrap run is forked by the server.
 *
 * XXX The need for code here is proof that the platform in question
 * is too brain-dead to provide a standard C execution environment
 * without help.  Avoid adding more here, if you can.
 */
static void
startup_hacks(const char *progname)
{
#if defined(__alpha)			/* no __alpha__ ? */
#ifdef NOFIXADE
	int			buffer[] = {SSIN_UACPROC, UAC_SIGBUS | UAC_NOPRINT};
#endif
#endif   /* __alpha */


	/*
	 * On some platforms, unaligned memory accesses result in a kernel trap;
	 * the default kernel behavior is to emulate the memory access, but this
	 * results in a significant performance penalty. We ought to fix PG not to
	 * make such unaligned memory accesses, so this code disables the kernel
	 * emulation: unaligned accesses will result in SIGBUS instead.
	 */
#ifdef NOFIXADE

#if defined(ultrix4)
	syscall(SYS_sysmips, MIPS_FIXADE, 0, NULL, NULL, NULL);
#endif

#if defined(__alpha)			/* no __alpha__ ? */
	if (setsysinfo(SSI_NVPAIRS, buffer, 1, (caddr_t) NULL,
				   (unsigned long) NULL) < 0)
		write_stderr("%s: setsysinfo failed: %s\n",
					 progname, strerror(errno));
#endif
#endif   /* NOFIXADE */


#ifdef WIN32
	{
		WSADATA		wsaData;
		int			err;

		/* Make output streams unbuffered by default */
		setvbuf(stdout, NULL, _IONBF, 0);
		setvbuf(stderr, NULL, _IONBF, 0);

		/* Prepare Winsock */
		err = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (err != 0)
		{
			write_stderr("%s: WSAStartup failed: %d\n",
						 progname, err);
			exit(1);
		}

		/* In case of general protection fault, don't show GUI popup box */
		SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	}
#endif   /* WIN32 */
}


/*
 * Help display should match the options accepted by PostmasterMain()
 * and PostgresMain().
 */
static void
help(const char *progname)
{
	printf(_("%s is the PostgreSQL server.\n\n"), progname);
	printf(_("Usage:\n  %s [OPTION]...\n\n"), progname);
	printf(_("Options:\n"));
#ifdef USE_ASSERT_CHECKING
	printf(_("  -A 1|0          enable/disable run-time assert checking\n"));
#endif
	printf(_("  -B NBUFFERS     number of shared buffers\n"));
	printf(_("  -c NAME=VALUE   set run-time parameter\n"));
	printf(_("  -d 1-5          debugging level\n"));
	printf(_("  -D DATADIR      database directory\n"));
	printf(_("  -e              use European date input format (DMY)\n"));
	printf(_("  -F              turn fsync off\n"));
	printf(_("  -h HOSTNAME     host name or IP address to listen on\n"));
	printf(_("  -i              enable TCP/IP connections\n"));
	printf(_("  -k DIRECTORY    Unix-domain socket location\n"));
#ifdef USE_SSL
	printf(_("  -l              enable SSL connections\n"));
#endif
	printf(_("  -N MAX-CONNECT  maximum number of allowed connections\n"));
	printf(_("  -o OPTIONS      pass \"OPTIONS\" to each server process (obsolete)\n"));
	printf(_("  -p PORT         port number to listen on\n"));
	printf(_("  -s              show statistics after each query\n"));
	printf(_("  -S WORK-MEM     set amount of memory for sorts (in kB)\n"));
	printf(_("  --NAME=VALUE    set run-time parameter\n"));
	printf(_("  --describe-config  describe configuration parameters, then exit\n"));
	printf(_("  --help          show this help, then exit\n"));
	printf(_("  --version       output version information, then exit\n"));

	printf(_("\nDeveloper options:\n"));
	printf(_("  -f s|i|n|m|h    forbid use of some plan types\n"));
	printf(_("  -n              do not reinitialize shared memory after abnormal exit\n"));
	printf(_("  -O              allow system table structure changes\n"));
	printf(_("  -P              disable system indexes\n"));
	printf(_("  -t pa|pl|ex     show timings after each query\n"));
	printf(_("  -T              send SIGSTOP to all backend servers if one dies\n"));
	printf(_("  -W NUM          wait NUM seconds to allow attach from a debugger\n"));

	printf(_("\nOptions for single-user mode:\n"));
	printf(_("  --single        selects single-user mode (must be first argument)\n"));
	printf(_("  DBNAME          database name (defaults to user name)\n"));
	printf(_("  -d 0-5          override debugging level\n"));
	printf(_("  -E              echo statement before execution\n"));
	printf(_("  -j              do not use newline as interactive query delimiter\n"));
	printf(_("  -r FILENAME     send stdout and stderr to given file\n"));

	printf(_("\nOptions for bootstrapping mode:\n"));
	printf(_("  --boot          selects bootstrapping mode (must be first argument)\n"));
	printf(_("  DBNAME          database name (mandatory argument in bootstrapping mode)\n"));
	printf(_("  -r FILENAME     send stdout and stderr to given file\n"));
	printf(_("  -x NUM          internal use\n"));

	printf(_("\nPlease read the documentation for the complete list of run-time\n"
	 "configuration settings and how to set them on the command line or in\n"
			 "the configuration file.\n\n"
			 "Report bugs to <pgsql-bugs@postgresql.org>.\n"));
}



static void
check_root(const char *progname)
{
#ifndef WIN32
	if (geteuid() == 0)
	{
		write_stderr("\"root\" execution of the PostgreSQL server is not permitted.\n"
					 "The server must be started under an unprivileged user ID to prevent\n"
		  "possible system security compromise.  See the documentation for\n"
				  "more information on how to properly start the server.\n");
		exit(1);
	}

	/*
	 * Also make sure that real and effective uids are the same. Executing as
	 * a setuid program from a root shell is a security hole, since on many
	 * platforms a nefarious subroutine could setuid back to root if real uid
	 * is root.  (Since nobody actually uses postgres as a setuid program,
	 * trying to actively fix this situation seems more trouble than it's
	 * worth; we'll just expend the effort to check for it.)
	 */
	if (getuid() != geteuid())
	{
		// 如果两者不一致，说明程序可能以 setuid 方式运行，存在安全风险，输出错误信息并退出程序。
		write_stderr("%s: real and effective user IDs must match\n",
					 progname);
		exit(1);
	}
#else							/* WIN32 */
	if (pgwin32_is_admin())
	{
		write_stderr("Execution of PostgreSQL by a user with administrative permissions is not\n"
					 "permitted.\n"
					 "The server must be started under an unprivileged user ID to prevent\n"
		 "possible system security compromises.  See the documentation for\n"
				  "more information on how to properly start the server.\n");
		exit(1);
	}
#endif   /* WIN32 */
}



static char *
get_current_username(const char *progname)
{
#ifndef WIN32
	struct passwd *pw;

	pw = getpwuid(geteuid());
	if (pw == NULL)
	{
		write_stderr("%s: invalid effective UID: %d\n",
					 progname, (int) geteuid());
		exit(1);
	}
	/* Allocate new memory because later getpwuid() calls can overwrite it. */
	return strdup(pw->pw_name);
#else
	long		namesize = 256 /* UNLEN */ + 1;
	char	   *name;

	name = malloc(namesize);
	if (!GetUserName(name, &namesize))
	{
		write_stderr("%s: could not determine user name (GetUserName failed)\n",
					 progname);
		exit(1);
	}

	return name;
#endif
}
