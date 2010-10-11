/*
 * AVTF SEA Sender server daemon rewrite in C using BSD kqueue.
 * (c) Vadim Goncharov <vadim_nuclight@mail.ru>, 2009.
 *
 * Covered by BSD license.
 *
 * Project started on 22.05.09 17:30 UTC+7.
 * Time spent: 46:12 before first run, 29:20 debugging before
 * putting server to full production use, 6 months after start.
 * 
 * $Id$
 *
 * Could be used as an example of using many kqueue() features,
 * see comments in code marked KQ FEATURE.
 *
 * It is a non-portable BSD-specific daemon for a custom hacky
 * SEA Sender protocol, originally invented and implemented by
 * Alexey Fadeev (#Kpot#) and Sergey Khilkov (J7). Protocol is
 * ugly by it's design and historic TCPSender's compatibilty roots,
 * but that's what we have to retain at least for some time, as
 * Java server is buggy. I decided to not implement some hacks
 * from that proto as it is not supposed to evolve much more, for
 * example, don't assume that full 16Mb-sized length can be used,
 * don't use IDs 1000-2000 for TCPSender, or don't support older
 * versions, etc.
 * Thanks to Semyon Tyan (Peek) for reverse-engineering protocol and
 * writing almost complete BlastCore client. Decompiled Java code of
 * server was used to write this server, but only as a hint (decompiler
 * didn't do everything, anyway). The main proto docs used are pictures
 * from Peek.
 *
 * In nomine Satani creo et destruo.
 */

#include <sys/types.h>
#include <sys/param.h>	/* MAXPATHLEN, roundup2() etc. */
#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/uio.h>	/* writev() */
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <sys/queue.h>
#include <sys/event.h>

/*** Global vars and constants. ***/

/* Some macros. */
#define ASSERT(e) ( (e) ? (void)0 : \
	(syslog(LOG_CRIT, "Abort: assertion failed in function %s at line %d of file %s", \
		   __func__, __LINE__, __FILE__), abort()))
#define ENOMEM_EXIT { \
		syslog(LOG_CRIT, "Not enough memory! Sorry, but daemon can't continue."); \
		exit(EX_OSERR);								 \
	}
#define dsyslog if (debug > 1) syslog
#define roundup2power2(x) ((1 << (fls(x) - 1) == x) ? x: 1 << ((fls(x) - 1) + 1))

#define ALARM_TIME	1
#define ARCH_TIMEOUT	90	/* Seconds between connection attempts. */
#define TIMER_INTRVL	10	/* Following timeouts must bt multiple of this. */
#define PING_TIMEOUT	120	/* Seconds between user pings. */
#define LOGIN_TIMEOUT	30	/* Time from connect to first cmd - or kill. */
#define DEF_MAXPENALTY	10	/* Seconds of flood without throttling. */
#define DEF_FKILLTHRESH	6	/* 6*10 default flood threshold to kill */
#define SYSLOG_IDENT "seasrvkqd"
#define MAXTXTIPLEN	15
#define INLDSIZE	16	/* bytes when dbuf will be too much overhead */
#define MAXBYTE		255	/* maximum value of byte, used as size for arrays */

/* SEA Sender constants. */
#define SEA_PORT		8732
#define SEA_C2S_USERCOMP	1	/* First cmd on login: send username & compname */
#define SEA_C2S_USERINFO	4	/* Set user info (second command on login) */
#define SEA_C2S_SENDMSG		2	/* Send message from client to server */
#define SEA_C2S_PING		3	/* Client pings server */
#define SEA_C2S_USERINFOREQ	5	/* Request someone's userinfo */
#define SEA_C2S_CHATREQ		7	/* Chat requests and messages */
#define SEA_C2S_CHATCANCEL	8	/* Chat cancel or "don't answer" */
#define SEA_C2S_LINKREQ		9	/* Request HTTP link to archive */
#define SEA_C2S_MUTE		10	/* "MUTE" on user */
#define SEA_C2S_AWAY		11	/* To away */
#define SEA_C2S_UNAWAY		12	/* From away */
/* cmd 13 from client to server was reserved for user picture */
#define SEA_C2S_CHANGENAME	14	/* Change user name on the fly */
#define SEA_C2S_PRINTER		15	/* User joins to Printers group */
#define SEA_C2S_UNPRINTER	16	/* User leaves Printers group */
#define SEA_S2C_USERLIST	1	/* List of all users */
#define SEA_S2C_ADDUSER		2	/* New user connected */
#define SEA_S2C_DELETEUSER	3	/* User disconnected */
#define SEA_S2C_MESSAGE		4	/* Incoming message */
#define SEA_S2C_PONG		5	/* Reply to client's ping */
#define SEA_S2C_USERINFO	6	/* Answer to userinfo request */
#define SEA_S2C_CHATREQMSGBEEP	7	/* Various chat commands */
#define SEA_S2C_CHATCANCEL	8	/* Chat cancel or "don't answer" */
#define SEA_S2C_LINK		9	/* Answer to archive link request */
#define SEA_S2C_MUTE		10	/* "User MUTE you" */
#define SEA_S2C_AWAY		11	/* User went to away */
#define SEA_S2C_UNAWAY		12	/* User went from away */
#define SEA_S2C_CHGALTSRVIP	13	/* Change alternative server IP */
#define SEA_S2C_CHANGENAME	14	/* User has changed name */

/* Structures. */

/*
 * Generic storage for data used multiple times, e.g. message data area.
 * Reference counting is simple: refcnt always equals to number of pointers
 * (outside of dbuf funcs and macros) carrying reference to this dbuf - usually
 * that means that you should always free dbuf at the end of your functions.
 */
struct dbuf {
	int	size;			/* size of that data */
	int	refcnt;			/* reference count */
	char	*data;			/* pointer to actual data area */
};

/*
 * Output buffer for client queues. Can utilize internal storage area and
 * externa dbuf at the same time, determined by non-NULL dbuf pointer and
 * total length field. In case length is greater than dbuf->size, then inline
 * data size is (dbuf->size - length), and inlinedata must be transmitted
 * BEFORE dbuf - useful for varying headers and constant payload while saving
 * space and utilizing write-combining.
 */
struct outbuf {
	STAILQ_ENTRY(outbuf) obq;	/* entry for this outbuf in queues */
	int	length;			/* total data in this outbuf */
	int	done;			/* transfer progress bytes counter */
	struct dbuf *data;		/* pointer to dbuf, NULL if inline */
	char	inlinedata[INLDSIZE];	/* small data is here, not in dbuf */
};
STAILQ_HEAD(outbufstq, outbuf);		/* type for header of outbuf queue */

/* Version of attach_dbuf() for outbuf's. */
#define LINK_DBUF(o, d)	do {					\
	(o)->data = (d);					\
	(d)->refcnt++;						\
} while(0);

/* Element of banned addresses list. */
struct banentry {
	SLIST_ENTRY(banentry) entries;	/* linked list */
	time_t		expire;
	in_addr_t	host;	/* banned IP in human-unreadable form */
	in_addr_t	mask;	/* subnet mask, usually /32 */
};

/* Element of flood control queue. */
struct flooder {
	STAILQ_ENTRY(flooder) entries;	/* linked list */
	time_t	when;			/* time of next allowed read */
	int 	fd;			/* fd for kevent() */
	void	*udata;			/* pointer to user */
};

/* Online user properties. */
struct user_t {
	LIST_ENTRY(user_t) entries;	/* entry in global user linked list */
	int	fd;			/* user's socket and ID in the SEA protocol */
	struct sockaddr_in addr;	/* user IP address and port */
	char 	txtaddr[MAXTXTIPLEN+1];	/* user IP in human-readable form */
	struct outbufstq outbufq;	/* output buffers queue */
	int	cmdlen;			/* SEA packet length - total to read */
	int	readlen;		/* already read bytes for current cmd */
	char	cmdbyte;		/* first byte of command (1 cmd per time) */
	char   *inbuf;			/* rest of command arg bytes */
	uint8_t	unamelen;		/* length of user name */
	char	username[MAXBYTE+1];	/* user name */
	uint8_t	cnamelen;		/* length of computer name */
	char	compname[MAXBYTE+1];	/* user's computer name */
	uint8_t	infolen;		/* length of user info (description) */
	char	userinfo[MAXBYTE+1];	/* user info (description) */
	char	faculty;		/* user faculty, ASCII + 48 */
	char	room[5+1];		/* user's room (3 digits, '-', 'a'or 'b') */
	char	version;		/* version of user client, e.g. 97 for 0.9.7.x */
	uint8_t	is_printer;		/* flag: member of alternative group */
	uint8_t	is_away;		/* flag: user is away */
	int	max_penalty;		/* threshold for flood control, per-client */
	time_t	penalty_timer;		/* time penaty for flood control */
	time_t	last_activity;		/* last time received frame from user */
};

/* Global variables. */
int	servsock;			/* our listening socket */
int	archsock;			/* connection to archiver */
struct sockaddr_storage archaddr;	/* archver's addr for socket functions */
int	kq;				/* for kevent() calls  */
int	debug = 0;			/* more detailed logging/not daemon */
int	strict = 0;			/* stricter protocol checking */
int	flood_threshold;		/* multiple of max_penalty to kill */
int	ban_timeout;			/* time for ban to expire */
int	quit;				/* got term signal */
int	alarm_triggered;		/* got timer */
int	cmdsig_triggered;		/* got admin command */
/*int	max_sendq;*/			/* how many frames allowed per user output queue */
int	usercount;			/* number of (fully connected) clients online */

/* List of all online and active users. */
LIST_HEAD(usrlist_t, user_t) userlist = LIST_HEAD_INITIALIZER(userlist);

/* List of banned addresses. */
SLIST_HEAD(banlist_t, banentry) banlist = SLIST_HEAD_INITIALIZER(banlist);

/* List of banned addresses. */
STAILQ_HEAD(flooderhead, flooder) flooders = STAILQ_HEAD_INITIALIZER(flooders);

/* Output buffer for archiver. */
static struct outbufstq archq = STAILQ_HEAD_INITIALIZER(archq);			

/* Link to message archive on the Web. */
static char archlink[MAXPATHLEN+1] = "http://sea.avtf.net/archive/";

/* Path to symlink for admin control commands. */
static char linkpath[MAXPATHLEN+1] = "/var/run/seasrvkq.ctl";

/* Path to archiver's Unix socket or textual inet address to connect or fd. */
static char archpath[sizeof(struct sockaddr_un)-24] = "";

/*** Functions. ***/

int
sock_nonblock(int sock)
{
	int flags;

	/* Non blocking mode */
	if ((flags = fcntl(sock, F_GETFL, 0)) < 0) {
		syslog(LOG_ERR, "sock_nonblock: fcntl(%d, F_GETFL): %m", sock);
		return (-1);
	}
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
		syslog(LOG_ERR, "sock_nonblock: fcntl(%d, F_SETFL): %m", sock);
		return (-1);
	}

	return (0);
}
	
void
term_signal(int z __unused)
{
	quit = 1;
}

/* This will execute every ALARM_TIME seconds. */
void
alarm_signal(int z __unused)
{
	alarm_triggered = 1;
	alarm(ALARM_TIME);
}

void
usr1_signal(int z __unused)
{
	cmdsig_triggered = 1;
}

void
init_sig(void)
{
	struct sigaction sv;  

	memset(&sv, 0, sizeof(struct sigaction));
	sv.sa_flags = 0;
	sigemptyset(&sv.sa_mask);
#ifdef SA_NOCLDWAIT
	sv.sa_flags |= SA_NOCLDWAIT;
#endif
#ifdef SA_NOCLDSTOP
	sv.sa_flags |= SA_NOCLDSTOP;
#endif
   
	sv.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sv, NULL);
	sigaction(SIGCHLD, &sv, NULL);

	sigaction(SIGHUP, &sv, NULL);
	sigaction(SIGUSR2, &sv, NULL);

	sv.sa_handler = term_signal;
 
	sigaction(SIGTERM, &sv, NULL);
	sigaction(SIGINT, &sv, NULL);

	sv.sa_handler = alarm_signal;

	sigaction(SIGALRM, &sv, NULL);   

	sv.sa_handler = usr1_signal;

	sigaction(SIGUSR1, &sv, NULL);   
}

/*
 * Turn already allocated by somebody memory area into dbuf.
 * Return value must be assigned to some pointer in caller so refcnt is 1.
 */
struct dbuf *
make_dbuf(void *data, int size)
{
	struct dbuf *d;

	d = malloc(sizeof(struct dbuf));
	if (d == NULL)
		ENOMEM_EXIT;
	bzero(d, sizeof(struct dbuf));
	d->size = size;
	d->refcnt = 1;
	d->data = data;

	return (d);
}

/*
 * Allocate new dbuf.  Can't return NULL.
 * Return value must be assigned to some pointer in caller so refcnt is 1.
 */
struct dbuf *
alloc_dbuf(int size)
{
	struct dbuf *d;
	void *data;

	data = malloc(size);
	if (data == NULL)
		ENOMEM_EXIT;
	d = make_dbuf(data, size);

	return (d);
}

/* Make another pointer referencing this dbuf (increment usage count). */
struct dbuf *
attach_dbuf(struct dbuf *d)
{
	ASSERT(d != NULL);

	d->refcnt++;
	return (d);
}

/*
 * Check if dbuf should be freed and free it if necessary - passed pointer
 * will be no longer used by caller.
 */
void
free_dbuf(struct dbuf *d)
{
	ASSERT(d != NULL);

	d->refcnt--;
	if (d->refcnt > 0)	/* still used by somebody, just decrement usage counter */
		return;
	if (d->data != NULL)
		free(d->data);
	free(d);
	return;
}

/* Find user struct by it's ID (fd) */
struct user_t *
fd2user(int fd)
{
	struct user_t *user;

	LIST_FOREACH(user, &userlist, entries)
		if (fd == user->fd)
			return (user);	

	/* Not found. */
	return (NULL);
}

/*
 * Add more data to descriptor's output buffer queue.
 *
 * In case dbuf is not NULL it is added to queue AFTER the plain data.
 *
 * Caller is responsible for dealing with descriptor itself and
 * freeing adata - it is copied to queue, while dbuf is linked, not copied.
 *
 * If caller don't use dbuf, combining of small strings will be attempted to
 * larger buffers, so caller may wish to write even 1-byte strings.
 */
void
append_outbufq(struct outbufstq *q, void *adata, int datalen, struct dbuf *adbuf)
{
	struct outbuf *obuf, *last;
	struct dbuf *tmpdbuf;

	ASSERT((q != NULL) && ((adbuf != NULL) || (adata != NULL) && (datalen > 0)));

	/* Just for safety. */
	if (adata == NULL)
		datalen = 0;

	/* 
	 * We have several cases of calling:
	 *
	 * 1) adata < INLDSIZE, no adbuf
	 * 2) adata > INLDSIZE, no adbuf
	 * 3) adata < INLDSIZE, has adbuf
	 * 4) adata > INLDSIZE, has adbuf
	 * 5) no adata, has adbuf
	 *
	 * and several states of output queue:
	 *
	 * a) no, transmitted or full last outbuf, always must alloc new one.
	 * b) last outbuf has inlinedata <= INLDSIZE-datalen, no dbuf.
	 * c) last outbuf has full inlinedata, no dbuf.
	 * d) last outbuf has dbuf, no matter how many inlinedata.
	 *    This is actually equivalent to (a).
	 *
	 * For simplicity, we will not try to repack data to always fit
	 * minimum space, because in outbuf dbuf always follows after the
	 * inlinedata, so this still be splitted on writing anyway. Thus,
	 * it has no sense to split 1 <= datalen <= 2*INLDSIZE sized data
	 * to fit a part into last->inlinedata, because dbuf will reside
	 * between two inlinedata's. So, too big plain data will always be
	 * turned to dbuf before adding, and in cases (2) and (4) we will
	 * have two dbuf's to add to queue. This allows to simplify things
	 * even more, use recursion and always behave as we are called with
	 * EITHER plain data OR adbuf.
	 */

	/*
	 * First, turn cases 1-5 to recursive calls, at last the only
	 * possible cases must be 1 and 5, after this block, always
	 * in subsequent calls.
	 */
	if (datalen > INLDSIZE) {
		/* for both cases 2 and 4 */
		tmpdbuf = alloc_dbuf(datalen); 
		memmove(tmpdbuf->data, adata, datalen);
		append_outbufq(q, NULL, 0, tmpdbuf); 
		if (adbuf != NULL)	/* case 4 */
			append_outbufq(q, NULL, 0, adbuf);
		free_dbuf(tmpdbuf);
		return;
	} else if ((adata != NULL) && (adbuf != NULL)) {
		/* case 3 */
		append_outbufq(q, adata, datalen, NULL);
		append_outbufq(q, NULL, 0, adbuf);
		return;
	}

	/*
	 * Second, decide if we can append data to existing last outbuf.
	 * We can't do it if it is already being transmitted or it has not
	 * enough space. In fact, select between states (a) and (b)/(c).
	 */
	last = STAILQ_LAST(q, outbuf, obq);	/* undefined ptr if queue is empty! */

	if ((STAILQ_EMPTY(q)) || (last->data != NULL) || (last->done > 0)) {
		/* State (a). */
		obuf = malloc(sizeof(struct outbuf));
		if (obuf == NULL)
			ENOMEM_EXIT;
		bzero(obuf, sizeof(struct outbuf));
		STAILQ_INSERT_TAIL(q, obuf, obq);

		/* Turn state (a) to states (b) and (c). */
		last = obuf;
		/* FALLTHROUGH */
	}

	if (adbuf != NULL) {
		/* cases 5b and 5c */
		LINK_DBUF(last, adbuf);
		last->length += adbuf->size;
	} else if (datalen + last->length <= INLDSIZE) {	/* case 1b */
		memmove(&last->inlinedata[last->length], adata, datalen);
		last->length += datalen;
	} else {
		/* case 1c */
		last->data = alloc_dbuf(datalen); 
		memmove(last->data->data, adata, datalen);
		last->length += datalen;
	}
}

/*
 * Try to write data from output queue to client's fd.
 * Returns number of bytes written, 0 on soft error, and -1 on hard error,
 * i.e. error which requires closing descriptors (caller can check errno).
 *
 * Only does writes, caller is responsible for select()/kqueue() handling.
 *
 * If size hint is specified (>0), then caller knows that so many bytes are
 * available in fd's output buffer, try to combine writes. Else try to write
 * until it is possible. 
 */
int
try_write(int fd, struct outbufstq *q, int hint)
{
	int n, len, nwritten = 0, iovcnt = 0, saved_errno;
	void *pos;
	struct iovec iov[IOV_MAX];
	struct outbuf *obuf;

	ASSERT((q != NULL) && (fd >= 0));

	/* Just for safety. */
	if (STAILQ_EMPTY(q))
		return (0);

	/*
	 * This is mostly a demonstration program, so we'll use writev()
	 * only once per call, and only if hint is specified. After then
	 * fall back to usual write(). Also do fallback if first chunk is
	 * already partially written.
	 */
	obuf = STAILQ_FIRST(q);
	if ((hint > 0) && (obuf->done == 0)) {
		/* First build the I/O vector. */
		n = 0;
		STAILQ_FOREACH(obuf, q, obq) {
			/* Too many of them? */
			if ((iovcnt >= IOV_MAX-2) || (n + obuf->length > hint))
				break;
			if (obuf->data != NULL) {
				iov[iovcnt].iov_base = obuf->inlinedata;
				iov[iovcnt].iov_len = obuf->length - obuf->data->size;
				iovcnt++;
				iov[iovcnt].iov_base = obuf->data->data;
				iov[iovcnt].iov_len = obuf->data->size;
			} else {
				iov[iovcnt].iov_base = obuf->inlinedata;
				iov[iovcnt].iov_len = obuf->length;
			}
			iovcnt++;
			n += obuf->length;
		}
		/* Actually try to do combined write. */
		nwritten = writev(fd, iov, iovcnt);
		saved_errno = errno;
		dsyslog(LOG_DEBUG, "debug: try_write(%d): writev() returned %d", fd, nwritten);
		errno = saved_errno;
		if (nwritten > 0) {
			/* Iterate and free fully written chunks of queue. */
			n = nwritten;
			obuf = STAILQ_FIRST(q);
			while ((obuf != NULL) && (obuf->length <= n)) {
				n -= obuf->length;
				if (obuf->data != NULL)
					free_dbuf(obuf->data);
				STAILQ_REMOVE_HEAD(q, obq);
				free(obuf);
				obuf = STAILQ_FIRST(q);
			}
			/* Last chunk may be partially written. */
			if (obuf != NULL)
				obuf->done = n;			
		} else  {	/* an error has occured */
			if (errno == EAGAIN)
				return (0);	/* no sense to retry early */
			if (errno == EINTR) {
				/*
				 * If interrupted by signal, automatically try
				 * again later by fallback to usual write() below.
				 */
				nwritten = 0;
			} else {
				syslog(LOG_ERR, "error: writev(%d): %m", fd);
				errno = saved_errno;
				return (-1);
			}
		}
		/* FALLTHROUGH */
	}

	/*
	 * Fallback case, no matter how many space available, handle each
	 * chunk in one or two calls to write().
	 */
	while (!STAILQ_EMPTY(q)) {
		obuf = STAILQ_FIRST(q);
		/*
		 * Determine we will write inlinedata or dbuf.
		 */
		if (obuf->data != NULL) {
			n = obuf->length - obuf->data->size;
			/* Is inlinedata finished? */
			if (obuf->done < n) {
				pos = (void*)&obuf->inlinedata[obuf->done];
				len = n - obuf->done;
			} else {
				pos = (void*)obuf->data->data;
				pos += obuf->done - n;
				len = obuf->length - obuf->done;
			}
		} else {
			pos = (void*)&obuf->inlinedata[obuf->done];
			len = obuf->length - obuf->done;
		}
		/* Buffer calculated, write it. */
		n = write(fd, pos, len);
		saved_errno = errno;
		dsyslog(LOG_DEBUG, "debug: try_write(%d): write() returned %d", fd, n);
		errno = saved_errno;
		if (n > 0) {
			nwritten += n;
		} else {	/* an error has occured */
			if ((errno == EAGAIN) || (errno == EINTR) || (n == 0))
				break;/* Let caller to handle this, but we still has the buffers. */
			else
				return (-1);	/* connection lost */	
		}
		/* Now check if chunk writing is complete, to free buffers. */
		obuf->done += n;
		if (obuf->done == obuf->length) {
			if (obuf->data != NULL)
				free_dbuf(obuf->data);
			STAILQ_REMOVE_HEAD(q, obq);
			free(obuf);
		}
		/*
		 * If that was writing inlinedata, next iteration will handle
		 * dbuf automatically, just by continue with the same obuf, as
		 * it is still at the head of the queue.
		 */
	}

	/* Successful return. */
	return (nwritten);
}

/*
 * Setup writing event on a descriptor with provided output queue.
 *
 * NOTE: This should be implemented another way (flag in struct),
 * or just not done at all - just call try_write() directly instead
 * of this and handle errors at caller. But our goal is to demonstrate
 * KQ FEATURE of disabled events, for other way see handling of archiver
 * sock. But remember that handling errors at every caller of try_write()
 * is far more complicated and potentially more error-prone than to defer
 * this error checks and disconnects to top-level functions. So this is
 * not just for demonstration.
 */
void
schedule_write(int fd, struct outbufstq *q)
{
	struct kevent kev;

	ASSERT((fd > 0) && (q != NULL));
	
	/*
	 * KQ FEATURE: we can have event still present in the kernel,
	 * but disabled and not returned to us. We use that for writung
	 * because kevent() will always return write availability if socket
	 * buffer has enough space, even if we have nothing to write.
	 *
	 * Also, because event is still kept in the kernel, we are more
	 * tolerate to errors - they shouldn't occur.
	 */
	EV_SET(&kev, fd, EVFILT_WRITE, EV_ENABLE, 0, 0, q);
	if ((kevent(kq, &kev, 1, NULL, 0, NULL) < 0) && (errno != EINTR))
		syslog(LOG_ERR, "schedule_write: enabling kevent: %m");
}

/*
 * Message archival function; archiver communication protocol.
 *
 * SEA SHIT: protocol must be featureful enough to support viewing older
 * messages by own means, at least in form like ICQ does with offline messages.
 * Instead, the only way in SEA protocol is to see public messages at the web
 * (via completely different program, browser) and no support for private msgs
 * at all. Moreover, the archiving is done at the original server, hard-coded
 * to direct HTML file writing or putting to MySQL database. It is better to
 * delegate this function to a different process/program to be more extendable
 * and customizable, may be to a special version of a client (bot), as still
 * only public messages are archived. It is arguable, though, that different
 * client (may be on a different host) is less reliable to connection (and thus
 * data) losses, so we'll better do this by server means, though not directly.
 *
 * Archiver is a separate process (and may be put on a different host, if one
 * wish), so archiving can be easily customized, but we don't want to invent
 * another complex protocol for that, so this is simple text line-oriented
 * (with byte count, though):
 *
 * A text line with case-insensitive first field and integer second field,
 * number of other space-separated fields depends on command:
 *
 *     cmd bytecount may be other args till end of line\n
 *
 * then $bytecount bytes of raw data (may be zero), then next line for next
 * command. This can be easily read and parsed by the following shell script:
 *
 * #!/bin/sh
 *
 * while read what bytes restofline; do
 *         msg=`dd bs=1 count=$bytes 2>/dev/null`
 *         echo what: $what rest of line: $restofline
 *         echo bytes: "$msg"
 * done
 *
 * Note #1: this protocol is used for other purposes, too, so archiver must
 * parse command and extract only (public) messages to save, if it wishes.
 *
 * Note #2: raw data can contain any bytes, e.g. line breaks in \r\n form,
 * while protocol itself delimits by Unix convention (\n only), be prepared.
 *
 * Here we define only message command in archiver protocol, for others see
 * comments to other functions.
 *
 * Format:
 * 
 *     MSG count src_id user_txtIP dst_id unixtime username[machinename]\n
 *
 * Example message from user John at machine FOOBAR (id=4) to all users
 * (id=0) at 2009-02-13 23:31:30 UTC, then message from user with spaces
 * in user and machine name, both with CR LF's in message texts:
 *
 *     MSG 14 4 192.168.0.5 0 1234567890 John[FOOBAR]
 *     Hi!
 *
 *     Test.
 *     MSG 8 5 192.168.0.6 0 1234567904 I am[GOD HERE]
 *     passed
 *
 * You can see that username[machinename] is actually one last argument because
 * it can contain argument-separating characters (spaces).
 */
void
archive_msg(struct user_t *user, int dstid, struct dbuf *msgtext)
{
	time_t curtime = time(NULL);
	char textline[MAXPATHLEN];	/* should be bigger than 512 */

	ASSERT((user != NULL) && (msgtext != NULL) && (dstid >= 0) && (dstid < 65536));

	textline[0] = '\0';
	snprintf(textline, MAXPATHLEN, "MSG %d %d %s %d %d %s[%s]\n",
			msgtext->size, user->fd, user->txtaddr, dstid,
			curtime, user->username, user->compname);

	/*
	 * XXX Should we put messages in queue when archiver isn't connected
	 * and even not trying to connect?
	 */
	if (archsock > 0) {
		append_outbufq(&archq, textline, strlen(textline), msgtext);
		try_write(archsock, &archq, 0);
	}
}

/*
 * Parse supplied text specification of address to connect into
 * 'struct sockaddr' of appropriate address family. Returns:
 * 
 *  -2 - if it is AF_INET address and port in form '1.2.3.4:5678'
 *  -1 - if it is an absolute path to Unix socket
 *   0  - if supplied text specification was invalid
 *  >0 - if it is a single integer number of already opened descriptor,
 *       then this number is returned (must be posittive)
 *
 * If 'place' pointer is non-NULL, then parsed address placed into there,
 * and in case of Unix socket, it is checked to be accessible.
 *
 * WARNING: there must be enough space at that address or buffer overflow
 * may occur! Using RFC 2553's 'struct sockaddr_storage' is recommended.
 */
int
parse_addr(struct sockaddr_storage *place, char *textaddr)
{
	struct sockaddr_in sa_sin;
	struct sockaddr_un sa_sun;
	long fd;
	char *cptr;

	ASSERT(textaddr != NULL);

	/* Unix socket? */
	if (textaddr[0] == '/') {
		if (strlen(textaddr) > sizeof(sa_sun.sun_path))
			return (0);	/* will be truncated thus invalid */

		/*
		 * No reason to accept unaccessible socket, but we can't
		 * syslog() this error while openlog() has not yet been
		 * called or caller may not want us to do syscalls.
		 */
		if (place && access(textaddr, R_OK|W_OK)) {
			syslog(LOG_ERR, "access: %m");
			return (0);
		}

		bzero(&sa_sun, sizeof(sa_sun));
		sa_sun.sun_family = AF_UNIX;
		strncpy(sa_sun.sun_path, textaddr, sizeof(sa_sun.sun_path));
		sa_sun.sun_len = sa_sun.sun_path[sizeof(sa_sun.sun_path)-1] == '\0'
			? SUN_LEN(&sa_sun) : sizeof(sa_sun);

		if (place)
			memcpy(place, &sa_sun, sizeof(sa_sun));

		return (-1);
	}

	/* Already opened file descriptor number? */
	fd = strtol(textaddr, &cptr, 10);
	if (*cptr != '\0')
		goto inet4;
	if ((fd > 0x7ffffffe) || (fd <= 0))
		return (0);
	else
		return (fd);

	/* The only case left is AF_INET - IPv4 with port. */
inet4:
	bzero(&sa_sin, sizeof(struct sockaddr_in));

	cptr = strchr(textaddr, ':');
	if (!cptr)
		return (0);
	*cptr = '\0';	/* XXX Hack! We should copy the string, not modify/restore it. */
	if (!inet_aton(textaddr, &sa_sin.sin_addr)) {
		*cptr = ':';
		return(0);
	}
	*cptr = ':';
	textaddr = ++cptr;
	fd = strtol(textaddr, &cptr, 10);
	if (*cptr != '\0')
		return(0);
	if ((fd > 65535) || (fd < 0))
		return (0);

	sa_sin.sin_family = AF_INET;
	sa_sin.sin_len = sizeof(struct sockaddr_in);
	sa_sin.sin_port = htons(fd);

	if (place)
		memcpy(place, &sa_sin, sizeof(sa_sin));

	return (-2);
}

/* 
 * Do a nonblocking connect on passed socket variable with setting
 * user data for keeping in kevent(). This function may be called on timer
 * event and must support doing nothing with already connected descriptor.
 *
 * This is a generic socket function, caller must provide us with already
 * parsed struct sockaddr, so this could be used for doing generic connects
 * (e.g. to archiver or other IM systems gateways).
 */
void
connect_sock(int *sock, void *udata, struct sockaddr *addr)
{
	struct kevent kev;
	int yes = 1;
	int ret, len;

	if (*sock > 0) {
		/* check if connected */
		len = sizeof(struct sockaddr_un);
		ret = getpeername(*sock, addr, &len);
		if ((ret == 0) || ((ret == -1) && (errno == ENOBUFS)))
			return;	/* OK, sock is still connected or can't check */
		if ((errno == ENOTSOCK)/*&& (*sock == parse_addr(NULL, archpath))*/)
			return;	/* OK, that's file or pipe on expected fd number */
		/* connection is absent, close and retry connect */
		if (errno != EBADF)
			close(*sock);
		*sock = -1;
	}

	/* prepare to connection */
	if ((*sock = socket(addr->sa_family, SOCK_STREAM, 0)) == -1)
		goto err;

	if (sock_nonblock(*sock) == -1)
		goto err;

	/* Error here is not critical - may be a Unix socket. */
	setsockopt(*sock, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int));

	/*
	 * Register events on this sock before connecting.
	 *
	 * KQ FEATURE: We use EV_CLEAR here so that event is kept
	 * permanently in the kernel but not returned every time as it
	 * would be in usual case (have space in socket buffer). Instead,
	 * only changes in write socket buffer will be reported, for example,
	 * when peer reads something or when error is encountered. So we,
	 * as opposed to EV_DISABLE method, do direct writes to socket without
	 * waiting for availability event.
	 */
	EV_SET(&kev, *sock, EVFILT_WRITE, EV_ADD|EV_CLEAR, 0, 0, udata);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0)
		goto err;

	/* perform connect */
	ret = connect(*sock, addr, addr->sa_len);
	if ((ret == -1) && (errno != EINPROGRESS)) {
		syslog(LOG_ERR, "connect: %m");
		goto err;
	}

	return;		/* connection will be continued in background */
err:
	if (*sock != -1)
		close(*sock);
	*sock = -1;
}

/*
 * Close socket and drain it's queue.
 */
void
disconnect_sock(int fd, struct outbufstq *outq)
{
	struct outbuf *obuf;

	ASSERT((fd > 0) && (outq != NULL));
	close(fd);

	while (!STAILQ_EMPTY(outq)) {
		obuf = STAILQ_FIRST(outq);
		STAILQ_REMOVE_HEAD(outq, obq);
		if (obuf->data != NULL)
			free_dbuf(obuf->data);
		free(obuf);
	}
}

void
reconnect_archiver(bool disconnect_and_reparse)
{
	/*
	 * Close archiver socket and drain it's queue.
	 *
	 * In any case we don't know if archiver has read next complete
	 * command, we also can't distinguish command bounds in our queue. So
	 * we must drain it completely, may be loosing some data (but archiver
	 * is optional facility anyway).
	 *
	 * XXX Note that data is added again to archiver's queue when
	 * connection attempt begins, that is, before it has finished and could
	 * be read, but if this attempt was unsuccessful, queue is cleared
	 * again. This doesn't allow to keep e.g. hours or days of archive data
	 * between connections, but that could be seen as excessive memory
	 * consumption prevention (effectively leak from admin's viewpoint if
	 * archiver will never connect).
	 */
	if ((archsock > 0) && disconnect_and_reparse)
		disconnect_sock(archsock, &archq);
	archsock = -1;

	/*
	 * Get the socket address. Our caller may have already parsed address
	 * to struct sockaddr, don't redo if so; fd number is allowed to be
	 * passed only one time, on the start of the program, because we can't
	 * do connects to descriptor numbers. Logging is also should be done
	 * in another place because we are called by timer many times between
	 * address changes.
	 */
	if (disconnect_and_reparse)
		if (parse_addr(&archaddr, archpath) >= 0)
			return;

	syslog(LOG_INFO, "initiating connect to archiver on %s", archpath);
	connect_sock(&archsock, &archq, (struct sockaddr*)&archaddr);
}

/*
 * Kill a user: close connection, unlink from lists, notify other users,
 * etc. cleanup. It is safe to call this on a struct of user which is
 * not yet fully logged in. Does actual disconnect without any reasons and
 * logging by default - it is responsibility of the caller to provide errno
 * (coskerr used only if non-zero) or another textual reason for kill.
 *
 * Pointer to user will become invalid after call.
 */
void
kill_user(struct user_t *user, int sockerr, char *reason)
{
	char buf[3];
	struct flooder *cf, *tf;
	struct user_t *curuser;
	struct kevent kev;

	ASSERT(user != NULL);

	/*
	 * Check if this is fully connected user or not yet completed login.
	 * If it is, unlink from list and inform others.
	 *
	 * XXX As we don't have LIST_PREV, fd2user() will check entire list,
	 * but we try to optimize for most cases via LIST_NEXT.
	 */
	if ((LIST_NEXT(user, entries) != NULL) || (fd2user(user->fd) != NULL)) {
		usercount--;
		LIST_REMOVE(user, entries);

		buf[0] = SEA_S2C_DELETEUSER;
		buf[1] = user->fd >> 8;
		buf[2] = user->fd & 0xff;

		LIST_FOREACH(curuser, &userlist, entries) {
			append_outbufq(&curuser->outbufq, buf, 3, NULL);
			schedule_write(curuser->fd, &curuser->outbufq);
		}
	} else {
		/*
		 * Delete login timeout timer.
		 * XXX Don't check error because we could be called from
		 * this timer trigger but also from other errors. Not the
		 * ideal solution...
		 */
		EV_SET(&kev, user->fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
		if ((kevent(kq, &kev, 1, NULL, 0, NULL) < 0))
			syslog(LOG_DEBUG, "deleting login timer kevent: %m");
	}

	/*
	 * If user is delayed in flood control queue, that information will
	 * become invalid, so clean it now.
	 */
	STAILQ_FOREACH_SAFE(cf, &flooders, entries, tf)
	       	if ((cf->fd == user->fd) && (cf->udata == user)) {
			STAILQ_REMOVE(&flooders, cf, flooder, entries);
			free(cf);
		}

	/* Perform logging, if caller wishes so. */
	if (reason)
		syslog(LOG_INFO, "client id=%d %s[%s] (%s:%hu) disconnected: %s",
			user->fd, user->username, user->compname, user->txtaddr,
			ntohs(user->addr.sin_port), reason);
	else if (sockerr) {
		errno = sockerr;
		syslog(LOG_INFO, "client id=%d %s[%s] (%s:%hu) disconnected: %m",
			user->fd, user->username, user->compname, user->txtaddr,
			ntohs(user->addr.sin_port));
	}

	/* Free resources. */
	if (user->inbuf != NULL)
		free(user->inbuf);
	disconnect_sock(user->fd, &user->outbufq);

	/* Finally free structure itself and destroy it for safety. */
	bzero(user, sizeof(struct user_t));
	free(user);
}

/*
 * Process next timer event. Called once per second. 
 * Expire banlist and flood control queues.
 */
void
process_timer(void)
{
	struct kevent kev;
	struct flooder *cf, *tf;
	struct banentry *cb, *tb;
	time_t curtime = time(NULL);
	int ret;

	/*
	 * First handle flood control queue. Re-enable reading clients whose
	 * time already came.
	 */
	STAILQ_FOREACH_SAFE(cf, &flooders, entries, tf) {
		if (curtime < cf->when)
			continue;

		EV_SET(&kev, cf->fd, EVFILT_READ, EV_ADD|EV_ONESHOT, NOTE_LOWAT, 4, cf->udata);
		if ((ret = kevent(kq, &kev, 1, NULL, 0, NULL)) < 0) {
			if (errno == EINTR)
				continue;	/* better luck on next pass */
			syslog(LOG_ERR, "process_timer: adding kevent: %m");

			/*
			 * We could handle ENOMEM as transient error,
			 * but that resource shortage yet again could
			 * be caused by flooders, so better we kill
			 * user to free some resources.
			 */
			kill_user(fd2user(cf->fd), 0, "error handling client in flood queue");
		}
		STAILQ_REMOVE(&flooders, cf, flooder, entries);
		free(cf);
	}

	/* Now purge banlist. */
	SLIST_FOREACH_SAFE(cb, &banlist, entries, tb)
		if (curtime >= cb->expire) {
			SLIST_REMOVE(&banlist, cb, banentry, entries);
			free(cb);
		}
}

/*
 * Check passed textual IP address against banlist.
 */
struct banentry *
check_banlist(char *textaddr, in_addr_t ipaddr)
{
	struct banentry *ban;
	time_t curtime = time(NULL);

	ASSERT(((textaddr != NULL) && (strlen(textaddr) <= MAXTXTIPLEN)) ||
		((ipaddr != INADDR_ANY) && (ipaddr != INADDR_NONE)));

	if (textaddr) {
		ipaddr = inet_addr(textaddr);
		if (ipaddr == INADDR_NONE)
			return (NULL);
	}

	SLIST_FOREACH(ban, &banlist, entries) {
		/* TODO: support -k addr/mask (may be port from avtnatpmpd) */
		if ((ban->host == (ipaddr & ban->mask)) && (curtime < ban->expire))
			return (ban);
	}

	return (NULL);
}

/*
 * Add an address to banlist.
 * Accepts either exact IP address or it's textual form, in which subnet mask
 * can be specified, e.g. '1.2.3.0/24' or '1.2.3.4' (the latter is equivalent
 * to '1.2.3.4/32'). Zero timeout could be specified to only text syntax (if
 * text form is passed), and negative to unban.
 * Returns 0 if success, -1 on syntax error, and -2 on malloc() failure.
 */
int
ban_address(char *textaddr, in_addr_t ipaddr, int timeout)
{
	time_t curtime = time(NULL);
	struct banentry *curban;
	char *ptr, tmptxt[MAXTXTIPLEN+4];
	struct in_addr hostnet;
	in_addr_t mask = 0xffffffff;	/* /32 by default */
	int mlen;

	if (textaddr) {
		strlcpy(tmptxt, textaddr, sizeof(tmptxt));
		ptr = strchr(tmptxt, '/');
		if (!ptr)
			mlen = 32;
		else {
			*ptr++ = '\0';
			mlen = atoi(ptr);
			if ((mlen < 0) || (mlen > 32))
				return (-1);
		}
		if (!inet_aton(tmptxt, &hostnet))
			return (-1);
		ipaddr = hostnet.s_addr;
		mask = htonl(mlen ? (~0 << (32 - mlen)) : 0);
	}

	if (timeout == 0)
		return (0);
	
	/*
	 * Check if we should modify existing ban or delete it.
	 * We do exact comparison, allocating new ban otherwise, and
	 * treat unbanning of non-banned address as successful.
	 */
	curban = check_banlist(NULL, ipaddr);
	if (curban) {
		if ((curban->host == ipaddr) && (curban->mask == mask)) {
			if (timeout < 0)
				SLIST_REMOVE(&banlist, curban, banentry, entries);
			else
				curban->expire = curtime + timeout;
			return (0);
		}
	} else if (timeout < 0)
		return (0);

	curban = malloc(sizeof (struct banentry));
	if (curban == NULL) {
		syslog(LOG_ERR, "can't allocate memory for ban: %m");
		return (-2);
	}
	bzero(curban, sizeof(struct banentry));
	SLIST_INSERT_HEAD(&banlist, curban, entries);
	curban->expire = curtime + timeout;
	curban->host = ipaddr;
	curban->mask = mask;
	/* XXX strlcpy(curban->txtaddr, textaddr, sizeof(curban->txtaddr)); */
	return (0);
}

/*
 * Handle signal from admin.
 *
 * So, we are doing control for daemon implementing tricky, illogical and
 * inconsistent protocol, so let's our daemon be crazy-controlled too!
 * OK, I'm just too lazy to implement config-file parsing or yet another
 * IPC protocol for this relatively simple task, and I'm not SO crazy to
 * make code duplication for each of brain-damaged way of control, so here
 * it is, one string as argument and several signals...
 *
 * Archiver protocol command for user info - each command for one user:
 * 
 *     USERINFO count user_id variables=value ... usercomp=username[machine]\n
 *
 * Here almost all variables from user_t go in this line in form 'var=value',
 * and bytecount speciifes length of user info which goes after this line.
 */
void
admin_command(int signo)
{
	int cmdlen, fd;
	char buf[4];
	char admcmd[MAXPATHLEN+1];
	char textline[MAXPATHLEN];
	in_addr_t ipaddr;
	/* time_t curtime = time(NULL); */
	struct user_t *curuser, *tmpuser;
	struct sockaddr_storage addr_stor;
	struct sockaddr_in *addr_in = (struct sockaddr_in*)&addr_stor;

	syslog(LOG_DEBUG, "entering admin_command() with signal %d", signo);

	bzero(&admcmd, sizeof(admcmd));
	cmdlen = readlink(linkpath, admcmd, MAXPATHLEN);
	if (cmdlen <= 0) {
		syslog(LOG_ERR, "readlink: %m");
		return;
	}

	ipaddr = inet_addr(admcmd);		/* or INADDR_NONE if not IP */
	fd = parse_addr(&addr_stor, admcmd);	/* if it is number, get it */
	if (fd > 0)				/* but inet(3) functions do */
		ipaddr = INADDR_NONE;		/* treat "13" as "13.0.0.0" */

	switch (signo) {
	case SIGUSR1:	/* kill a user and ban it for standard flood ban time */
		/*
		 * We can ban user by ID, by IP, by address:port of it's
		 * connection, and finally, ban a subnet, killing all matching
		 * users. In the latter case, we do so by banning subnet and
		 * then checjing each user against banlust. We try to keep only
		 * one entry in banlist.
		 */
		if ((strchr(admcmd, '/')) || (ipaddr != INADDR_NONE))
			ban_address(admcmd, INADDR_NONE, ban_timeout);
		else if (fd == -2)
			ban_address(NULL, addr_in->sin_addr.s_addr, ban_timeout);
		LIST_FOREACH_SAFE(curuser, &userlist, entries, tmpuser)
			if (((fd > 0) && (fd == curuser->fd)) ||
			    ((ipaddr != INADDR_NONE) && !strcmp(admcmd, curuser->txtaddr)) ||
			    ((fd == -2) && !bcmp(&curuser->addr, addr_in, addr_in->sin_len)) ||
			    check_banlist(curuser->txtaddr, INADDR_NONE)) {
				syslog(LOG_WARNING, "client id=%d %s[%s] killed by admin",
						curuser->fd, curuser->username, curuser->compname);
				/* If it was user id, we must ban here. */
				if (fd > 0)
					ban_address(curuser->txtaddr, INADDR_NONE, ban_timeout);
				kill_user(curuser, 0, "killed by admin");
			}
		break;
	case SIGUSR2:	/* set archive link, debug, ban timeout or unban user */
		if (fd > 0) {
			ban_timeout = (fd > flood_threshold * DEF_MAXPENALTY) ?
				fd : flood_threshold * DEF_MAXPENALTY;
			syslog(LOG_NOTICE, "setting ban timeout to: %d", ban_timeout);
		} else if (ban_address(admcmd, INADDR_NONE, -1) == 0)
			syslog(LOG_NOTICE, "unbanned %s", admcmd);
		else if (!strcmp(admcmd, "debug")) {
			debug = (debug + 1) % 3;
			syslog(LOG_INFO, "setting debug level to %d", debug);
			setlogmask(LOG_UPTO(debug > 0 ? LOG_DEBUG : LOG_INFO));
		} else {
			strlcpy(archlink, admcmd, sizeof(archlink));
			syslog(LOG_NOTICE, "setting archive URL to: %s", admcmd);
		}
		break;
	case SIGHUP:
		if (fd >= 0) {
			syslog(LOG_ERR, "invalid archiver address/path specification: %s",
					(fd > 0) ? "descriptor number not allowed after start" : admcmd);
			return;
		}
		memcpy(&archaddr, &addr_stor, sizeof(struct sockaddr_storage));
		if (!strncmp(admcmd, archpath, sizeof(archpath))) {
			syslog(LOG_NOTICE, "repeated SIGHUP, forcing reconnect to archiver");
			reconnect_archiver(true);
		} else {
			syslog(LOG_INFO, "setting archiver path to: %s", admcmd);
			strlcpy(archpath, admcmd, sizeof(archpath));
		}
		break;
	case SIGINFO:	/* dump information to archiver about all or some users */
		if (archsock <= 0)
			return;
		LIST_FOREACH(curuser, &userlist, entries)
			if (((fd > 0) && (fd == curuser->fd)) ||
			    ((ipaddr != INADDR_NONE) && !strcmp(admcmd, curuser->txtaddr)) ||
			    ((fd == -2) && !bcmp(&curuser->addr, addr_in, addr_in->sin_len)) ||
			    (!strcmp(admcmd, "all"))) {
				textline[0] = '\0';
				snprintf(textline, MAXPATHLEN, "USERINFO %d %d "
						"ip=%s port=%hu " /* XXX outbufq? */
						"cmdlen=%d readlen=%d inbuf=%p "
						"faculty=%hhu room=%s version=%hhu "
						"printer=%hhu away=%hhu max_penalty=%d "
						"penalty_timer=%d last_activity=%d "
						"usercomp=%s[%s]\n",
						curuser->infolen, curuser->fd, 
						curuser->txtaddr, ntohs(curuser->addr.sin_port),
						curuser->cmdlen, curuser->readlen, curuser->inbuf,
						curuser->faculty, curuser->room, curuser->version,
						curuser->is_printer, curuser->is_away, curuser->max_penalty,
						curuser->penalty_timer, curuser->last_activity,
						curuser->username, curuser->compname);
				append_outbufq(&archq, textline, strlen(textline), NULL);
				if (curuser->infolen > 0)
					append_outbufq(&archq, curuser->userinfo, curuser->infolen, NULL);
			}
		if (debug) {	/* dump global variables */
			textline[0] = '\0';
			snprintf(textline, MAXPATHLEN, "GLOBALVARS 0 debug=%d "
					"strict=%d flood_threshold=%d ban_timeout=%d "
					"usercount=%d archsock=%d archpath=%s\n",
					debug, strict, flood_threshold, ban_timeout,
					usercount, archsock, archpath);
			append_outbufq(&archq, textline, strlen(textline), NULL);
		}
		try_write(archsock, &archq, 0);
		break;
	case SIGWINCH:	/* change alternative address */
		if (ipaddr == INADDR_NONE)
			syslog(LOG_ERR, "admin_command: IPv4 address expected instead of %s", admcmd);
		else {
			syslog(LOG_NOTICE, "sending new secondary server IP address (%s) to all clients", admcmd);
			buf[0] = SEA_S2C_CHGALTSRVIP;
			LIST_FOREACH(curuser, &userlist, entries) {
				append_outbufq(&curuser->outbufq, buf, 1, NULL);
				append_outbufq(&curuser->outbufq, &ipaddr, 4, NULL);
				schedule_write(curuser->fd, &curuser->outbufq);
			}
		}
		break;
	default:
		syslog(LOG_ERR, "admin_command: unknown signal %d", signo);
	}
}

/*
 * Change some chars in user or comp name to safe ones.
 *
 * SEA SHIT: This function should be unnecessary - see long
 * comment in process_usercomp() where this func is called.
 */
void
escape_name(unsigned char *name, int len)
{
	int i;

	ASSERT((name != NULL) && (len > 0) && (len < 256));

	for (i = 0; i < len; i++)
		switch (name[i]) {
		case '>':
			name[i] = ')';
			break;
		case '<':
			name[i] = '(';
			break;
		default:
			if (name[i] < 32)
				name[i] = '_';
		}
}

/*
 * SEA SHIT: original server didn't check buffer bounds.
 */
#define CHECK_LENGTH(c) do { 						\
	if (user->cmdlen > (c))	{					\
		syslog(strict ? LOG_ERR : LOG_WARNING,			\
			"%s: client id=%d has %d trailing bytes in command #%hhu", \
			__func__, user->fd, user->cmdlen - (c), user->cmdbyte);	\
		if (strict)						\
			goto invalid_format;				\
	}								\
} while(0);

/*
 * Process login command - username and computer name.
 */
int
process_usercomp(struct user_t *user)
{
	uint16_t userid;
	struct user_t *curuser;
	struct dbuf *uinfobuf;
	char buf[576];
	struct kevent kev;

	ASSERT(user != NULL);

	if (user->cmdbyte != SEA_C2S_USERCOMP) {
		syslog(LOG_ERR, "process_usercomp: first command from client id=%d was %hhu, not #1",
				user->fd, user->cmdbyte);
		/*
		 * SEA SHIT: And original server didn't kill such user
		 * while even not responding to login cmd later!
		*/
		return (-1);
	}
	if (user->cmdlen < 5)
		goto invalid_format;
	ASSERT(user->inbuf != NULL);
	user->unamelen = user->inbuf[0];
	/*
	 * SEA SHIT: original server didn't check buffer bounds.
	 */
	if ((user->unamelen == 0) || (user->unamelen > user->cmdlen-4))
		goto invalid_format;
	/*
	 * We don't need to NUL-terminate as entire user struct was zeroed.
	 */
	memcpy(user->username, &user->inbuf[1], user->unamelen);
	user->cnamelen = user->inbuf[user->unamelen+1];
	if ((user->cnamelen == 0) || (user->cnamelen + user->unamelen + 3 > user->cmdlen))
		goto invalid_format;
	memcpy(user->compname, &user->inbuf[user->unamelen+2], user->cnamelen);
	CHECK_LENGTH(user->cnamelen + user->unamelen + 3);

	/*
	 * SEA SHIT:
	 * Now user will be logged in, but we still need to check names for
	 * validity. Yes, the right place for this would be to just escape it
	 * in archiver, not here, but original server checked only for HTML
	 * '<' and '>', while we potentially need to escape all control chars
	 * for C string handling and newlines (to not mess our own logs and
	 * archiver's line-based text protocol). Also, original server killed
	 * user if his first username char was space - just because fucking
	 * client sorts groups just by name! That is, group names are started
	 * from space, despite the fact they are hardcoded to client. But we
	 * need to keep some compatibility - and we don't know if that fucked
	 * client don't use unescaped HTML somewhere inside (must protect them
	 * also). So username still can't start from space, but we'll change
	 * it to underscore, the same with other control chars, and replace
	 * HTML angle braces, too (which will also slightly simplify archiver).
	 */
	if (user->username[0] == 32)
		user->username[0] = '_';
	escape_name(user->username, user->unamelen);
	escape_name(user->compname, user->cnamelen);

	/*
	 * Now we must hook the user into user list and inform other users
	 * about this connect.
	 *
	 * SEA SHIT: Original server take special measures (by 20 to 50 lines
	 * of Java source code, depends on what to count) to send info about
	 * this user to itself first, and then process list of other users.
	 * We don't know if this is really needed for client, to be his info
	 * really first (as he knows his ID, he can find himself), so we'll
	 * keep this behavior, but by more elegant way: just hook user to the
	 * head of the list.
	 */
	usercount++;
	userid = htons((uint16_t)(user->fd & 0xffff));
	buf[0] = SEA_S2C_USERLIST;
	memcpy(&buf[1], &userid, 2);
	buf[3] = strlen(user->txtaddr);
	append_outbufq(&user->outbufq, buf, 4, NULL);
	append_outbufq(&user->outbufq, user->txtaddr, strlen(user->txtaddr), NULL);
	buf[0] = usercount / 256;
	buf[1] = usercount % 256;
	append_outbufq(&user->outbufq, buf, 2, NULL);

	/*
	 * Build repeated part, the same for all users. As this notification
	 * is the same for all users except our new, we'll keep it in dbuf,
	 * but userlist data will be in one instance, so we don't worry
	 * about dbufs. 
	 */
	uinfobuf = alloc_dbuf(user->unamelen + user->cnamelen + 5);

	uinfobuf->data[0] = SEA_S2C_ADDUSER;
	memcpy(&uinfobuf->data[1], &userid, 2);
	uinfobuf->data[3] = user->unamelen;
	memcpy(&uinfobuf->data[4], user->username, user->unamelen);
	uinfobuf->data[user->unamelen+4] = user->cnamelen;
	memcpy(&uinfobuf->data[user->unamelen+5], &user->compname, user->cnamelen);

	/* Inform others and construct userlist in one loop. */
	LIST_INSERT_HEAD(&userlist, user, entries);
	LIST_FOREACH(curuser, &userlist, entries) {
		userid = htons((uint16_t)(curuser->fd & 0xffff));
		append_outbufq(&user->outbufq, &userid, 2, NULL);
		append_outbufq(&user->outbufq, &curuser->unamelen, 1, NULL);
		append_outbufq(&user->outbufq, curuser->username, curuser->unamelen, NULL);
		append_outbufq(&user->outbufq, &curuser->cnamelen, 1, NULL);
		append_outbufq(&user->outbufq, curuser->compname, curuser->cnamelen, NULL);
		if (user != curuser)
			append_outbufq(&curuser->outbufq, NULL, 0, uinfobuf);
		schedule_write(curuser->fd, &curuser->outbufq);
	}
	free_dbuf(uinfobuf);
	
	/*
	 * SEA SHIT: We don't support TCPSender - the better way to do is
	 * by creating gateways. But there are many cases when TCPSender is
	 * assumed... we'll always return stubs, here - zero TCP usercount.
	 */
	buf[0] = 0;
	buf[1] = 0;
	append_outbufq(&user->outbufq, buf, 2, NULL);

	/*
	 * Now user has logged in, delete his login timer:
	 * if user will disconnect before timer fires, then
	 * login_timeout() will be called with ptr to freed memory.
	 */
	EV_SET(&kev, user->fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	if ((kevent(kq, &kev, 1, NULL, 0, NULL) < 0))
		syslog(LOG_DEBUG, "deleting login timer kevent: %m");

	syslog(LOG_INFO, "client id=%d %s[%s] logged in from %s:%hu",
			user->fd, user->username, user->compname, user->txtaddr, ntohs(user->addr.sin_port));
	return (0);

invalid_format:
	syslog(LOG_ERR, "process_usercomp: client id=%d from %s login failure: protocol format error",
			user->fd, user->txtaddr);
	return (-1);
}

/*
 * Process fully available SEA protocol command from client.
 */	
int
process_command(struct user_t *user)
{
	uint16_t userid, msglen;
	struct user_t *curuser;
	unsigned char buf[MAXBYTE+1];
	uint8_t buf102msghdr[8];	/* message header for proto version >= 102 */
	uint32_t bigmsglen;		/* to place to hdr for proto version >= 102 */
	struct dbuf *bcastbuf, *bigbuf;

	ASSERT(user != NULL);
	dsyslog(LOG_DEBUG, "process_command: debug fd=%d: entering with cmd #%d and cmdlen=%d",
			user->fd, user->cmdbyte, user->cmdlen);

	/*
	 * First check if this is first command in the connection - is
	 * the user logged in.
	 */
	if ((user->unamelen == 0) && (user->cnamelen == 0))
		return process_usercomp(user);
	else if (user->cmdbyte == SEA_C2S_USERCOMP) {
		syslog(LOG_ERR, "process_command: client id=%d issues #1 while already logged in as %s[%s]",
				user->fd, user->username, user->compname);
		/* Original server ignores it, let for us to do it too. */
		return (0);
	}

	/*
	 * Provide simple flood control.
	 *
	 * We have a simple model, to penalize client for constant
	 * number of seconds in the future (IRC-like) then begin to throttle
	 * client if penalty looks ahead of current time more then allowed
	 * threshold (default 10 seconds), then kill and ban client for a
	 * while, if flood continues and threshold is exceeded even more
	 * (default 60 seconds).
	 *
	 * In addition to that, we have a logarithmic penalty of the command
	 * (message) length, but that is applied only to long commands. We
	 * still want to control client trying to flood the server with many
	 * short commands. The goal is to allow the client to be not throttled
	 * in usual small message mode, and throttling threshold should not be
	 * exceeded immediately after the first command - that is, goal is to
	 * allow sending e.g. one chat message per 2 seconds and one group
	 * message per 10 seconds.
	 * 
	 * The threshold of logarithmic algorithm was chosen for client to be
	 * penalized by 1 second for length < 256, 2 seconds for 256 to 512,
	 * 3 seconds for 512 to 1024, and so on. Some commands (like away)
	 * have only this form of control, some add constant time, so e.g.
	 * chat command with length under 256 will add 2 seconds total, and
	 * with length more than 256 -> 3 seconds (protocol don't allow more).
	 *
	 * SEA SHIT: original server didn't have ANY form of control, so it was
	 * easy to spam all the users by 1000 group messages per minute!
	 */
	user->last_activity = time(NULL);
	if (user->penalty_timer < user->last_activity)
		user->penalty_timer = user->last_activity;
	if (user->cmdlen > 256)
		user->penalty_timer += ffs(roundup2power2(user->cmdlen)) - 8;
	else
		user->penalty_timer++;

	/* Central daemon's switch, providing flood control also. */
	switch (user->cmdbyte) {
	case SEA_C2S_USERINFO:		/* 4 */
		user->penalty_timer++;
		if (user->cmdlen < 9)	/* we allow info to be zero length */
			goto invalid_format;
		ASSERT(user->inbuf != NULL);
		user->faculty = user->inbuf[0];
		memcpy(&user->room[0], &user->inbuf[1], 5);
		user->infolen = user->inbuf[6];
		if (user->infolen + 9 > user->cmdlen)	/* need to read version byte */
			goto invalid_format;
		memcpy(&user->userinfo[0], &user->inbuf[7], user->infolen);
		user->version = user->inbuf[user->infolen + 7];
		CHECK_LENGTH(user->infolen + 9);
		syslog(LOG_INFO, "client id=%d %s[%s]: userinfo set to faculty=%hhu room=%s version=%hhu and %d info bytes",
				user->fd, user->username, user->compname, user->faculty, user->room, user->version,
				user->infolen);
		/*
		 * Now, as this client supports SEA_C2S_USERINFO command, he
		 * also supports being away, so we must inform which users
		 * are away.
		 *
		 * SEA SHIT: this could be better done by extending userlist
		 * with several fields rather then emulating setting other
		 * clients away at the moment of connection. And all of this is
		 * done only after certain client version, not for every
		 * supporting this cmd!
		 */
		if (user->version < 96)
			break;
		LIST_FOREACH(curuser, &userlist, entries)
			if ((curuser != user) && (curuser->is_away)) {
				userid = htons((uint16_t)(curuser->fd & 0xffff));
				buf[0] = SEA_S2C_AWAY;
				append_outbufq(&user->outbufq, buf, 1, NULL);
				append_outbufq(&user->outbufq, &userid, 2, NULL);
			}
		schedule_write(user->fd, &user->outbufq);
		break;
	case SEA_C2S_SENDMSG:		/* 2 */
		/*
		 * SEA SHIT: Original server was controlled via messages with
		 * special format from user with special name '#Kpot#' (the
		 * author of the system). This way is hacky in two ways -
		 * first, server must parse general-purpose message command
		 * instead of special controlling commands, second, there is
		 * absolutely NO authentication from malicious users - original
		 * client prohibited using such nickname, but that is trivially
		 * hacked in binary settings files, so EVERYONE can control the
		 * server AND clients (by setting malicious own alternative
		 * server) this way. So I decide to not implement this, and
		 * instead control server by local UNIX means. These commands,
		 * which are implemented other way, were distinguished by first
		 * byte of message text:
		 *
		 * '*123.213.231.222' - send proto cmd #13 (SEA_S2C_CHGALTSRVIP)
		 *                      to make clients set alternate server
		 *                      address to this IP
		 * '|123.213.231.22|' - ban (actually just kill) all clients
		 *                      with this IP
		 */
		if (user->cmdlen < 7)
			goto invalid_format;
		ASSERT(user->inbuf != NULL);
		memcpy(&msglen, &user->inbuf[4], 2);
		msglen = ntohs(msglen);
		if (user->cmdlen < msglen + 7)	/* we'll handle message with zero length later */
			goto invalid_format;
		/*
		 * Ver 102 extension is allowed ONLY when it can't fit to 64K.
		 */
		if (user->version < 102)
			CHECK_LENGTH(msglen + 7)
		else if ((user->cmdlen < 65535 + 7) && (msglen + 7 < user->cmdlen)) {
			syslog(LOG_ERR, "client id=%d %s[%s] tried msglen=%hu but proto ver 102 disallowed on cmdlen < 64K",
				user->fd, user->username, user->compname, msglen);
			goto invalid_format;
		}

		/*
		 * Begin to prepare output headers in local buffer.
		 */
		bzero(buf, 8);
		buf[0] = SEA_S2C_MESSAGE;
		userid = htons((uint16_t)(user->fd & 0xffff));
		memcpy(&buf[1], &userid, 2);

		/*
		 * Now process destination user id and don't send empty msgs.
		 * SEA SHIT: original server allowed this while it is almost
		 * always a bug in client or flooding user.
		 */
		memcpy(&userid, user->inbuf, 2);
		userid = ntohs(userid);
		if (msglen == 0) {
			syslog(LOG_WARNING, "ignoring zero-length message from client id=%d %s[%s] to id=%hu",
					user->fd, user->username, user->compname, userid);
			break;
		}
		user->penalty_timer += 8;	/* not so strict flood control */
		syslog(LOG_INFO, "message from client id=%d %s[%s] to id=%hu (%hu/%d bytes)",
				user->fd, user->username, user->compname, userid, msglen, user->cmdlen - 7);

		/*
		 * SEA SHIT: message to printers is considered private!
		 */
		if (userid != 0)
			buf[3] = 1;
		/*
		 * SEA SHIT: printers group is flagged by TWO bytes instead of
		 * one, greatly reducing possibility to extend protocol - these
		 * two bytes were reserved in prior versions.
		 */
		if (userid == 65535) {
			buf[4] = 1;
			buf[5] = 1;
		}
		memcpy(&buf[6], &user->inbuf[4], 2);	/* message length */

		/*
		 * Now extract message text to dbuf, which could be used for
		 * archival purposes, too - this is why we don't place headers
		 * to dbuf but to temporary buffer (archiver wants only text).
		 */
		bcastbuf = alloc_dbuf(msglen);
		memcpy(bcastbuf->data, &user->inbuf[6], msglen);
		archive_msg(user, userid, bcastbuf);

		/*
		 * Handle long messages for protocol version 102 and later.
		 *
		 * While an older client will get only msglen bytes (part of
		 * message), a newer client must get a full length in header.
		 * Thus, message length bytes will be a lower two bytes of
		 * total length, and the higher (third), MSB byte is split
		 * two to nibbles in the two printers flag bytes.
		 */
		bigbuf = NULL;	/* also a flag, need to send or not */
		if ((user->version >= 102) && (user->cmdlen > msglen + 7)) {
			bigmsglen = user->cmdlen - 7;
			bigbuf = alloc_dbuf(bigmsglen - msglen);
			memcpy(bigbuf->data, &user->inbuf[6 + msglen], bigmsglen - msglen);

			/* Now do bits-and-bytes tricks... */
			memcpy(buf102msghdr, buf, 8);
			bigmsglen = htonl(bigmsglen);
			memcpy(&buf102msghdr[4], &bigmsglen, 4);

			/*
			 * Now buf102msghdr[5..7] bytes are ready, copy flags
			 * byte from 102+ client (whatever there will be in
			 * upper 7 bits in later versions?) and restore
			 * printer flag, if any.
			 */
			buf102msghdr[4] = user->inbuf[2];
			buf102msghdr[4] &= 0xfe; /* clear if not to printers */
			buf102msghdr[4] |= buf[4] & 0x01;
		}

		/*
		 * Then actually send msg.
		 */
		buf[8] = buf[9] = 0;
		LIST_FOREACH(curuser, &userlist, entries)
			if ((userid == 0) ||
			    (userid == curuser->fd) ||
			    (userid == 65535) && (curuser->is_printer) && (curuser->version >= 97)) {
				/*
				 * XXX hack: 102 aplies only to >64K, but
				 * prio/flags should be set for smaller
				 * messages, too. So we must patch this byte
				 * every time...
				 */
				buf[4] = (userid == 65535) ? 1 : 0;
				if (curuser->version >= 102)
					buf[4] |= user->inbuf[2] & 0xfe;

				/* Actual appending. */
				if ((curuser->version >= 102) && bigbuf) {
					append_outbufq(&curuser->outbufq, buf102msghdr, 8, bcastbuf);
					append_outbufq(&curuser->outbufq, NULL, 0, bigbuf);
				} else
					append_outbufq(&curuser->outbufq, buf, 8, bcastbuf);
				/*
				 * SEA SHIT: due to TCPSender support, server
				 * appended to message 1-byte len, username,
				 * 1-byte len, compname, but only if source
				 * ID=0, otherwise just one zero byte. We don't
				 * support it but still need to do this.
				 */
				append_outbufq(&curuser->outbufq, &buf[8], 1, NULL);
				schedule_write(curuser->fd, &curuser->outbufq);
			}		
		free_dbuf(bcastbuf);
		if (bigbuf)
			free_dbuf(bigbuf);
		break;
	case SEA_C2S_PING:		/* 3 */
		CHECK_LENGTH(1);
		buf[0] = SEA_S2C_PONG;
		append_outbufq(&user->outbufq, buf, 1, NULL);
		schedule_write(user->fd, &user->outbufq);
		syslog(LOG_DEBUG, "process_command: debug fd=%d: Ping? Pong!", user->fd);
		break;
	case SEA_C2S_USERINFOREQ:	/* 5 */
		user->penalty_timer++;
		if (user->cmdlen < 3)
			goto invalid_format;
		ASSERT(user->inbuf != NULL);
		CHECK_LENGTH(3);
		memcpy(&userid, user->inbuf, 2);
		userid = ntohs(userid);
		curuser = fd2user(userid);
		syslog(LOG_DEBUG, "process_command: debug fd=%d: userinfo req about %d", user->fd, userid);
		if (curuser == NULL)
			break;	/* Not found */
		buf[0] = SEA_S2C_USERINFO;
		append_outbufq(&user->outbufq, buf, 1, NULL); 
		append_outbufq(&user->outbufq, &curuser->faculty, 1, NULL);
		append_outbufq(&user->outbufq, &curuser->room, 5, NULL);
		append_outbufq(&user->outbufq, &curuser->infolen, 1, NULL);
		if (curuser->infolen > 0)
			append_outbufq(&user->outbufq, &curuser->userinfo, curuser->infolen, NULL);
		buf[0] = curuser->version;
		buf[1] = strlen(curuser->txtaddr);
		append_outbufq(&user->outbufq, buf, 2, NULL);
		append_outbufq(&user->outbufq, curuser->txtaddr, strlen(curuser->txtaddr), NULL);
		schedule_write(user->fd, &user->outbufq);
		break;
	case SEA_C2S_CHATREQ:		/* 7 */
	case SEA_C2S_CHATCANCEL:	/* 8 */
		user->penalty_timer++;
		if (user->cmdlen < 3)
			goto invalid_format;
		ASSERT(user->inbuf != NULL);
		memcpy(&userid, user->inbuf, 2);
		userid = ntohs(userid);
		curuser = fd2user(userid);
		syslog(LOG_DEBUG, "process_command: debug fd=%d: chat %s to %d", user->fd,
				(user->cmdbyte == SEA_C2S_CHATREQ) ? "req/text" : "cancel", userid);
		if (curuser == NULL)
			break;	/* Not found */
		/*
		 * We do a trick here - chat is entirely client-to-client
		 * thing, server doesn't pay attention to anything except IDs,
		 * even length is the same. So we just patch ID in our inbuf
		 * and then just copy this to destination user.
		 *
		 * SEA SHIT: that was even not so for versions < 94! But I
		 * don't want to support that SO old shit.
		 */
		userid = htons((uint16_t)(user->fd & 0xffff));
		memcpy(user->inbuf, &userid, 2);
		append_outbufq(&curuser->outbufq, &user->cmdbyte, 1, NULL);
		append_outbufq(&curuser->outbufq, user->inbuf, user->cmdlen - 1, NULL);
		schedule_write(curuser->fd, &curuser->outbufq);
		break;
	case SEA_C2S_LINKREQ:		/* 9 */
		CHECK_LENGTH(1);
		buf[0] = SEA_S2C_LINK;
		buf[1] = strlen(archlink);
		append_outbufq(&user->outbufq, buf, 2, NULL);
		append_outbufq(&user->outbufq, archlink, strlen(archlink), NULL);
		schedule_write(user->fd, &user->outbufq);
		syslog(LOG_INFO, "client id=%d %s[%s] requested archlink, sending %hhu bytes",
				user->fd, user->username, user->compname, buf[1]);
		break;
	case SEA_C2S_MUTE:		/* 10 */
		if (user->cmdlen < 3)
			goto invalid_format;
		ASSERT(user->inbuf != NULL);
		CHECK_LENGTH(3);
		memcpy(&userid, user->inbuf, 2);
		userid = ntohs(userid);
		curuser = fd2user(userid);
		syslog(LOG_DEBUG, "process_command: debug fd=%d: mute to %d", user->fd, userid);
		if (curuser == NULL)
			break;	/* Not found */
		if (curuser->version < 96)
			break;	/* SEA SHIT: older version support */
		userid = htons((uint16_t)(user->fd & 0xffff));
		buf[0] = SEA_S2C_MUTE;
		append_outbufq(&curuser->outbufq, buf, 1, NULL);
		append_outbufq(&curuser->outbufq, &userid, 2, NULL);
		schedule_write(curuser->fd, &curuser->outbufq);
		break;
	case SEA_C2S_AWAY:		/* 11 */
	case SEA_C2S_UNAWAY:		/* 12 */
		CHECK_LENGTH(1);
		user->is_away = (user->cmdbyte == SEA_C2S_AWAY) ? 1 : 0;
		syslog(LOG_DEBUG, "process_command: debug fd=%d: setting is_away=%d", user->fd, user->is_away);
		buf[0] = user->cmdbyte;
		userid = htons((uint16_t)(user->fd & 0xffff));
		memcpy(&buf[1], &userid, 2);
		LIST_FOREACH(curuser, &userlist, entries)
			if (curuser->version >= 96) {
				append_outbufq(&curuser->outbufq, buf, 3, NULL);
				schedule_write(curuser->fd, &curuser->outbufq);
			}		
		break;
	case SEA_C2S_CHANGENAME:	/* 14 */
		user->penalty_timer++;
		if (user->cmdlen < 3)
			goto invalid_format;
		ASSERT(user->inbuf != NULL);
		user->unamelen = user->inbuf[0];
		if (user->cmdlen < user->unamelen + 2)
			goto invalid_format;
		CHECK_LENGTH(user->unamelen + 2);
		strncpy(buf, user->username, MAXBYTE+1); /* XXX for syslog */
		bzero(user->username, sizeof(user->username));
		memcpy(user->username, &user->inbuf[1], user->unamelen);
		/* SEA SHIT: see long comment in process_usercomp(). */
		escape_name(user->username, user->unamelen);
		if (user->username[0] == 32)
			user->username[0] = '_';
		syslog(LOG_INFO, "client id=%d %s[%s] changes name to %s",
				user->fd, buf, user->compname, user->username);
		/*
		 * Now broadcast changed username - as this could be big but
		 * the same, use dbuf.
		 */
		bcastbuf = alloc_dbuf(user->unamelen + 4);
		bcastbuf->data[0] = SEA_S2C_CHANGENAME;
		userid = htons((uint16_t)(user->fd & 0xffff));
		memcpy(&bcastbuf->data[1], &userid, 2);
		bcastbuf->data[3] = user->unamelen;
		memcpy(&bcastbuf->data[4], user->username, user->unamelen);
		LIST_FOREACH(curuser, &userlist, entries)
			if (curuser->version >= 97) {
				append_outbufq(&curuser->outbufq, NULL, 0, bcastbuf);
				schedule_write(curuser->fd, &curuser->outbufq);
			}		
		free_dbuf(bcastbuf);
		break;
	case SEA_C2S_PRINTER:		/* 15 */
		CHECK_LENGTH(1);
		user->is_printer = 1;
		syslog(LOG_INFO, "client id=%d %s[%s] joins printers group",
				user->fd, user->username, user->compname);
		break;
	case SEA_C2S_UNPRINTER:		/* 16 */
		CHECK_LENGTH(1);
		user->is_printer = 0;
		syslog(LOG_INFO, "client id=%d %s[%s] leaves printers group",
				user->fd, user->username, user->compname);
		break;
	default:
		syslog(LOG_WARNING, "process_command: unknown command code #%hhu from client id=%d %s[%s]",
				user->cmdbyte, user->fd, user->username, user->compname);
	}
#undef CHECK_LENGTH

	return (0);

invalid_format:
	syslog(LOG_ERR, "process_command: killing client id=%d %s[%s]: protocol format error (command #%hhu, length %d)",
			user->fd, user->username, user->compname, user->cmdbyte, user->cmdlen);
	return (-1);
}

/*
 * Accept new client.
 */
void
accept_client(void)
{
	struct kevent kev[2];
	struct sockaddr_in cli_addr;
	struct user_t *user;
	int ret, fd, clilen = sizeof(struct sockaddr_in), yes = 1;

	ASSERT(kev != NULL);

retry:
	fd = accept(servsock, (struct sockaddr *)&cli_addr, &clilen);
	dsyslog(LOG_DEBUG, "debug: entering accept_client: accept() returned fd=%d (%m)", fd);
	if ((fd < 0) && (errno == EINTR))
		goto retry;
	if (fd <= 0)	/* XXX Our architecture and protocol prohibits id=0. */
		return;
	if ((sock_nonblock(fd) == -1) ||
	    (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) == -1)) {
		syslog(LOG_ERR, "accept_client: sock_nonblock()/setsockopt(): %m");
		close(fd);
		return;
	}

	if (check_banlist(NULL, cli_addr.sin_addr.s_addr)) {
		/*
		 * TODO: implement writing to socket notification
		 * for user about ban 
		 */
		syslog(LOG_INFO, "ban active for IP %s, closing connection on fd=%d",
				inet_ntoa(cli_addr.sin_addr), fd);
		goto accept_failed;
	}

	user = malloc(sizeof(struct user_t));
	if (user == NULL) {
		syslog(LOG_ERR, "accept_client: malloc: %m");
		close(fd);
		return;
	}
	bzero(user, sizeof(struct user_t));
	user->fd = fd;
	user->last_activity = time(NULL);
	memcpy(&user->addr, &cli_addr, sizeof(struct sockaddr_in));

	/* We can't work without textual version of IP address. */
	if (!inet_ntop(AF_INET, &cli_addr.sin_addr, user->txtaddr, sizeof(user->txtaddr))) {
		syslog(LOG_ERR, "inet_ntop: %m");
		goto accept_failed;
	}
	syslog(LOG_DEBUG, "received connection from %s:%hu on fd=%d", user->txtaddr,
			ntohs(cli_addr.sin_port), fd);

	/* Init critical vars. */
	STAILQ_INIT(&user->outbufq);
	user->max_penalty = DEF_MAXPENALTY;	/* TODO: make this customizable. */

	/*
	 * At this time user struct is initialized to minimum - and
	 * not yet plugged into userlist. All what we can here is
	 * to wait initail command from client - and we can optimize
	 * by waiting for at least minimal-sized full SEA_C2S_USERCOMP
	 * command, not just SEA packet length (KQ FEATURE).
	 *
	 * We also won't defer addinbg writing notifications - kevent() will
	 * return ENOENT in schedule_write() if only do EV_ENABLE there without
	 * EV_ADD; also, this will allocate kernel memory for event right here.
	 */
	EV_SET(&kev[0], user->fd, EVFILT_READ, EV_ADD|EV_ONESHOT, NOTE_LOWAT, 8, user);
	EV_SET(&kev[1], user->fd, EVFILT_WRITE, EV_ADD, 0, 0, &user->outbufq);
	while ((ret = kevent(kq, kev, 2, NULL, 0, NULL)) < 0) {
		if (errno != EINTR) {
			syslog(LOG_ERR, "accept_client: initial user kevent: %m");
			goto accept_failed;
		}
	}

	/*
	 * Set up a personal timer to fire if client issues no command in
	 * required interval. We don't strictly check error here because
	 * it is not critical and something will occur later anyway. This
	 * is not the best way to do things. though.
	 */
	EV_SET(&kev[0], user->fd, EVFILT_TIMER, EV_ADD|EV_ONESHOT, 0, LOGIN_TIMEOUT*1000, user);
	if ((kevent(kq, kev, 1, NULL, 0, NULL) < 0))
		syslog(LOG_INFO, "accept_client: adding login timer kevent: %m");

	/* We don't care about writing to client before his first cmd. */

	/* Finished accepting. */
	return;

accept_failed:
	close(fd);
	free(user);
	return;
}

/*
 * Either normal read or the end of connection.
 */
void
handle_read(int fd, struct user_t *user, u_short kqflags, u_int sockerr, intptr_t sizehint)
{
	struct kevent kev;
	struct flooder *curflooder;
	unsigned char buf[4];
	int ret;
	time_t curtime;

	ASSERT((user != NULL) && (fd == user->fd));
	dsyslog(LOG_DEBUG, "debug: entering handle_read(%d, %p, %#hx, %u, %d)",
			fd, user, kqflags, sockerr, sizehint);

	if (kqflags & EV_EOF) {
		/*
		 * Connection was closed by other side.
		 * XXX how many bytes left
		 *
		 * KQ FEATURE: we have errno in fflags, don't need
		 * to call read() just to know reason.
		 */
		if (sockerr)
			kill_user(user, sockerr, NULL);
		else
			kill_user(user, 0, "EOF from client (connection closed by other side)");
		return;
	}

	/*
	 * What do we read? We use KQ FEATURE to return an event only
	 * once via EV_ONESHOT, and ability to not return it until
	 * specified number of bytes will be available, via NOTE_LOWAT.
	 * Thus, we process byte stream in of two states, either:
	 * - reading 3 byte SEA packet length + 1 byte cmd, or
	 * - reading the rest of the packet (of specified length).
	 * By using water mark, we are able to read header at once,
	 * without complex buffers for header and for data, and switch
	 * between states with zero or non-zero data length.
	 *
	 * KQ FEATURE: we know from kevent() how many we have to read, in
	 * sizehint, so we could process both states while we are here if
	 * there are enough bytes to read.
	 */
	if (user->cmdlen != 0)
		goto read_body;

read_header:
	/*
	 * Current state: reading header.
	 */
	ret = read(fd, buf, 4);
	if (ret < 0)
		if (errno == EINTR)
			goto read_header;	/* Interrupted by signal, retry. */
		else {
			kill_user(user, errno, NULL);
			return;
		}
	else if ((ret > 0) && (ret < 4))	/* Should never occur. */
		syslog(LOG_CRIT, "handle_read: fd=%d: read() impossibly returned <4 (%d) bytes of header",
				fd, ret);

	/* Successful read, parse. */
	user->cmdlen = ((buf[0] << 16) | (buf[1] << 8) | (buf[2])) & 0xffffff;
	user->cmdbyte = buf[3];
	user->readlen = 1;	/* off by one to simplify math with read() */
	sizehint -= 4;		/* exclude header */
	syslog(LOG_DEBUG, "handle_read(%d): received header with cmd #%hhu, starting to read %d body bytes",
			fd, user->cmdbyte, user->cmdlen);
	if ((user->cmdlen > 65535) && (user->version < 102))
		syslog(LOG_WARNING, "abnormally big command length %d for command %hhu on fd=%d from %s:%hu",
				user->cmdlen, user->cmdbyte, user->fd,
				user->txtaddr, ntohs(user->addr.sin_port));
	if (strict && (user->cmdlen > 65536 + 7) && (user->version < 102)) {
		syslog(LOG_ERR, "killing client (possible loss of sync, buffer bytes: %02hhx %02hhx %02hhx %02hhx)",
				buf[0], buf[1], buf[2], buf[3]);
	}
	if (user->cmdlen == 0) {
		syslog(LOG_ERR, "zero command length from %s:%hu, killing user id=%d",
				user->txtaddr, ntohs(user->addr.sin_port), fd);
		kill_user(user, 0, "SEA protocol violation");
		return;
	}

	/* Is that single-byte cmd or we have to read (and allocate) more? */
	if (user->cmdlen != 1) {
		user->inbuf = malloc(user->cmdlen-1);
		if (user->inbuf == NULL) {
			syslog(LOG_ERR, "handle_read: malloc: %m");
			kill_user(user, 0, "can't allocate input buffer for client");
			return;
		}
	}
	if ((user->cmdlen == 1) || (sizehint == 0))	/* Skip reading body. */
		goto read_done;

	/* Enough bytes to read in one call or need to schedule reading more? */
	if (sizehint < user->cmdlen - 1) {
		/*
		 * No EV_ONESHOT - this could be triggered
		 * multiple times until entire command is read.
		 */
		EV_SET(&kev, user->fd, EVFILT_READ, EV_ADD, NOTE_LOWAT, 1, (void*)user);
		while ((ret = kevent(kq, &kev, 1, NULL, 0, NULL)) < 0) {
			if (errno != EINTR) {
				syslog(LOG_ERR, "handle_read: adding kevent: %m");
				kill_user(user, 0, "kevent() failed for client");
				return;
			}
		}
	}
	/* FALLTHROUGH - had at least some bytes to read. */

read_body:
	/*
	 * Current state: reading rest of the command.
	 */
	ret = read(fd, &user->inbuf[user->readlen - 1],
			sizehint > (user->cmdlen - user->readlen) ?
			(user->cmdlen - user->readlen) : sizehint);
	if (ret >= 0)
		user->readlen += ret;
	else if (errno != EINTR) {
		kill_user(user, errno, NULL);
		return;
	}

read_done:
	/* Was the command reading complete, so we could process it? */
	if (user->cmdlen != user->readlen)
		return;

	ret = process_command(user);
	if (user->inbuf != NULL) {
		free(user->inbuf);
		user->inbuf = NULL;
	}
	if (ret) {
		kill_user(user, 0, "SEA protocol violation");
		return;
	}

	/* Switch state to begin reading next cmd. */
	sizehint -= user->readlen - 1;
	user->cmdlen = 0;

	/*
	 * Flood control: schedule next read immediately or delay it.
	 * If we have even more bytes enough to read next command, and
	 * flood control alllows it, do it instead of return.
	 */
	if (user->last_activity + user->max_penalty < user->penalty_timer) {
		curtime = time(NULL);
		if (user->penalty_timer - user->last_activity >= user->max_penalty * flood_threshold) {
			/* Was delayed too many times, now kill it, arrgh! */
			ban_address(user->txtaddr, INADDR_NONE, ban_timeout);
			kill_user(user, 0, "excessive flood"); /* XXX report by how many */
			return;
		}
		curflooder = malloc(sizeof (struct flooder));
		if (curflooder == NULL) {
			/* We may be short of resources due to flooders! */
			kill_user(user, 0, "excessive flood");
			return;
		}
		bzero(curflooder, sizeof(struct flooder));
		STAILQ_INSERT_TAIL(&flooders, curflooder, entries);
		curflooder->when = curtime + 2;
		curflooder->fd = fd;
		curflooder->udata = user;
	} else if (sizehint >= 4)	/* enough for next command header? */
		goto read_header;
	else {
		EV_SET(&kev, user->fd, EVFILT_READ, EV_ADD|EV_ONESHOT, NOTE_LOWAT, 4, (void*)user);
		while ((ret = kevent(kq, &kev, 1, NULL, 0, NULL)) < 0) {
			if (errno != EINTR) {
				syslog(LOG_ERR, "handle_read: adding kevent: %m");
				kill_user(user, 0, "kevent() failed for client");
				return;
			}
		}
	}

	return;	/* Success. */
}

/*
 * Handle write event. This is used for two purposes - normal write and
 * as notifification of ending connection attempt to archiver.
 */
void
handle_write(int fd, struct outbufstq *obufq, u_short kqflags, u_int sockerr, intptr_t sizehint)
{
	struct kevent kev;
	int ret;

	ASSERT((obufq != NULL) && (fd > 0));
	dsyslog(LOG_DEBUG, "debug: entering handle_write(%d, %p, %#hx, %u, %d)",
			fd, obufq, kqflags, sockerr, sizehint);

	/* Connection was closed by other side? */
	if (kqflags & EV_EOF)
		goto write_err;

	/* KQ FEATURE: kevent() gives data amount available in write buffer */
	ret = try_write(fd, obufq, sizehint);
	/* errno is passed unchanged, we could check it here now. */
	if (ret == -1) {
		sockerr = errno; /* Because it may be overwritten by close() */
		goto write_err;
	}
	/* Successful otherwise. */
	if (STAILQ_EMPTY(obufq) && (fd != archsock)) {
		/* Deschedule writes. */
		EV_SET(&kev, fd, EVFILT_WRITE, EV_DISABLE, 0, 0, obufq);
		if ((kevent(kq, &kev, 1, NULL, 0, NULL) < 0) && (errno != EINTR))
			syslog(LOG_ERR, "handle_write: disabling kevent: %m");
	}
	return;

write_err:
	/*
	 * Hard error, so disconnect user here; kill_user() will close() for us.
	 *
	 * Archiver socket needs different handling.
	 */
	if (fd != archsock) {
		kill_user(fd2user(fd), sockerr, NULL);
		return;
	}

	/*
	 * Was it closed by error? If so, wait a little until timer will
	 * trigger next time, or try to reconnect immediately otherwise.
	 */
	if (sockerr) {
		errno = sockerr;
		syslog(LOG_ERR, "connection to archiver lost: %m");
	} else
		syslog(LOG_INFO, "archiver closed connection (%s)",
				STAILQ_EMPTY(obufq) ? "clean" :
				"our buffer still has data");
	disconnect_sock(archsock, &archq);
	archsock = -1;
}

/*
 * Triggers every ARCH_TIMEOUT seconds - either ping existing connection
 * or initiate new one.
 *
 * Archiver protocol command for pings of archiver - a server current time:
 * 
 *     TIME 0 unixtime\n
 *
 * Here bytecount is always zero and timestamp serves addition purpose: it
 * allows to determine in archiver log rough time when server connection
 * was loosed. The whole thing is a little hacky, but that's the nature of
 * TCP/IP: the archiver is allowed to close it's writing end at any moment
 * still continuing to read our messages. So we can't rely on reading EOF
 * and must ping archiver periodically in hope OS will detect disconnect as
 * early as it could, not many hours later with the first message after the
 * idle period, losing that message.
 */
void
handle_pingtimer(void *udata)
{
	time_t curtime = time(NULL);
	char textline[MAXPATHLEN];
	struct user_t *user, *tmpuser;
	int timeout;
	uint8_t pong;

	/*
	 * KQ FEATURE: this is using of passed udata, but this function don't
	 * really needs it (login_timeout() do). In addition, this whole
	 * archiver-handling funcs system sucks :( It is not so generic
	 * as I want it to be, but I have no time to rewrite (it works),
	 * so let it it be SO stupid way of using passed udata variable...
	 */
	ASSERT((udata == &archq) || (udata == NULL));

	if (udata) {
		/*
		 * Archiver timeouts.
		 */
		textline[0] = '\0';
		snprintf(textline, MAXPATHLEN, "TIME 0 %d\n", curtime);

		if (archsock > 0) {
			append_outbufq(&archq, textline, strlen(textline), NULL);
			try_write(archsock, &archq, 0);
		} else {
			reconnect_archiver(false);
		}
	} else {
		/*
		 * Check clients for timeouts.
		 */
		LIST_FOREACH_SAFE(user, &userlist, entries, tmpuser) {
			/*
			 * SEA SHIT: 10 minutes for native client, 2 minutes for
			 * BlastCore, but has to wait a little more - client may
			 * issue it's own ping, and our pong may reset it's own
			 * ping timer, so we'll not get last_activity increase!
			 */
			timeout = user->version < 98 ? PING_TIMEOUT * 5 : PING_TIMEOUT;
			timeout += TIMER_INTRVL * 2;
			if ((curtime - user->last_activity > timeout) &&
			    (curtime - user->last_activity <= timeout + TIMER_INTRVL)) {
				/*
				 * Try to pong reply, in hope client will
				 * understand, but only once (timer fires often).
				 */
				pong = SEA_S2C_PONG;
				append_outbufq(&user->outbufq, &pong, 1, NULL);
				schedule_write(user->fd, &user->outbufq);
				syslog(LOG_INFO, "forced pong to client id=%d %s[%s]", user->fd,
						user->username, user->compname);
			} else if (curtime - user->last_activity > timeout + PING_TIMEOUT) {
				/*
				 * No input command within interval.
				 */
				kill_user(user, 0, "ping timeout");
			}
		}
	}
}

/*
 * Login timeout.
 *
 * Check if user is still not logged in, and if so, kill him.
 * Thie is triggered only once.
 */
void
login_timeout(void *udata)
{
	struct user_t *user = udata;

	ASSERT(udata != NULL);

	if ((user->unamelen == 0) && (user->cnamelen == 0))
		kill_user(user, 0, "login timeout");
}

/*
 * Body of an event loop - process one event.
 */
void
event_loop(void)
{
	struct kevent kev;
	int ret;

	/*
	 * KQ will only return EV_ERROR if there were changes AND some of them
	 * were errorneous, so we will not check it below (information from
	 * FreeBSD 6.2 kernel sources).  Note that FreeBSD 8 will have another
	 * mechanism, EV_RECEIPT, but it is not yet available at the moment.
	 */
	ret = kevent(kq, NULL, 0, &kev, 1, NULL);
	if (errno != EINTR)
	syslog(LOG_DEBUG, "event_loop: debug: ret=%d errno=%d kev={ %d, %hd, %#hx, %u, %d, %p }",
			ret, errno, kev.ident, kev.filter, kev.flags, kev.fflags, kev.data, kev.udata);
	if (ret != 1)
		return;

	switch (kev.filter) {
	case EVFILT_READ:
		if (kev.ident == servsock)
			while (kev.data-- > 0)	/* KQ FEATURE - listen backlog */
				accept_client();
		else	/* It's either normal read or the end of connection. */
			handle_read(kev.ident, kev.udata, kev.flags, kev.fflags, kev.data);
		break;
	case EVFILT_WRITE:
		/*
		 * Data is available for writing or connection attempt has finished.
		 */
		handle_write(kev.ident, kev.udata, kev.flags, kev.fflags, kev.data);
		break;
	case EVFILT_TIMER:
		/*
		 * Connection timer expired or login timer expired.
		 * KQ FEATURE: Let's demonstrate kqueue() timers, we have two
		 * persistent ones, in addition to main SIGALRM timer, there we
		 * don't care about timer number (just NULL or data). All other
		 * timers are EV_ONESHOT - deleted after first fire. We use them
		 * to check expired logins.
		 */
		if (kev.ident <= 1)
			handle_pingtimer(kev.udata);
		else
			login_timeout(kev.udata);
		break;
	case EVFILT_SIGNAL:
		/*
		 * KQ FEATURE: With kqueue we can monitor even those signals which have
		 * no handler set (marked as SIG_IGN). Moreover, kev.data returns the
		 * number of times the signal has occurred since the last call to
		 * kevent(), but our program don't need this information.
		 */
		admin_command(kev.ident);
		break;
	default:
		syslog(LOG_WARNING, "event_loop: unexpected kevent filter %d", kev.filter);
	}
}

/* Print short help about command line and exit. */
void
usage(char *proctitle, char full)
{
	fprintf(stderr,
		"Usage: %s [-dqs] [-c path] [-a addr] [-u URL] [-f num] [-t sec]\n\n",
		proctitle);
	fprintf(stderr, (full == 'h') ?
		"This is a server daemon for a custom SEA Sender protocol, see comments at the\n"
		"beginning of source code for more details.\n\n"
		"Options:\n\n"
		"  -d\tDo not fork; enable debug (twice for extra info)\n"
		"  -c\tPath to control commands symlink, defaults to /var/run/seasrvkq.ctl\n"
		"  -q\tBe quiet to syslog (log fewer info); ignored when used with -d\n"
		"  -s\tEnable stricter protocol format checks (kill client on error)\n"
		"  -a\tAddress specification for archiver to connect to (see below)\n"
		"  -u\tURL of archiver web page to answer to clients\n"
		"  -f\tFlood threshold coefficient determinig when client will be killed\n"
		"  -t\tTimeout for temporary bans (both manual and auto) of IP addresses\n\n"
		"Server supports connection to separate archiver process using simple protocol\n"
		"(see comments in source code, this may be even simple shell script), address\n"
		"can be specified as either ipaddr:port, path to Unix domain socket or the\n"
		"preopened file descriptor number, in the latter case on-failure reconnects to\n"
		"archiver are not supported, and daemon could be started from Bourne shells\n"
		"using redirection e.g. like this:\n\n"
		"  %s -a 3 3>&1 | /path/to/archiver.sh\n\n"
		"Server also implements primitive IRC-like flood control on clients by first\n"
		"throttling when clinets floods more than allowed max_penalty time (default 10\n"
		"seconds). If client continues to flood more than flood_threshold * max_penalty\n"
		"seconds (default flood threshold is 6 giving 1 minute), then it is killed and\n"
		"banned for -t secs (can't be less flood_threshold * max_penalty) by resetting\n"
		"connection requests (because SEA clients always try to reconnect immediately).\n"
		"These bans are temporary, so you should consider tcpdrop(8) and firewall bans\n"
		"for malicious users.\n\n"
		"Daemon is controlled via placing command as a destination of control symlink\n"
		"and then issuing one ot the supported signals to daemon process, e.g. to kill\n"
		"(and ban for current ban timeout) all users with IP address 1.2.3.4, you do:\n\n"
		"  ln -s 1.2.3.4 /var/run/seasrvkq.ctl; killall -USR1 seasrvkqd\n\n"
		"Daemon always requires something to be present in the control symlink when\n"
		"is signal caught, and uses slightly weird system of modifying behaviour based\n"
		"on whether symlink contains positive integer number, IP address, ipaddr:port,\n"
		"IP address/mask in CIDR format (e.g. 1.2.3.0/24), some keyword or any other\n"
		"string. Currently supported signals are:\n\n"
		"  SIGUSR1  Kill and ban user(s) with specified ID, address or address:port\n"
		"           of it's conection. Address is always banned for usual timeout,\n"
		"           regardless of whether users from it are currently connected.\n"
		"  SIGUSR2  Set ban timeout to specified number of seconds (-t), unban address\n"
		"           (or address/mask) or set archiver URL for responses to clients (-u).\n"
		"           If keyword is 'debug', cycle to next debug (-d) level (0 after 2).\n"
		"  SIGHUP   Set archiver socket path/address to specified ipaddr:port or Unix\n"
		"           domain socket path. Same as -a, except preopened descriptor number\n"
		"           here is not allowed. Only sets address variable for future use, to\n"
		"           force reconnect send SIGHUP twice with the same addr spec.\n"
		"  SIGINFO  Print to archiver socket full information about user(s) with\n"
		"           specified ID, address or ipaddr:port of it's connection, or info\n"
		"           about all users if symlink equals to keyword 'all'. Also dump some\n"
		"           of the global variables when running in debug mode.\n"
		"  SIGWINCH Takes IP address and sends it in protocol command #13 to all clients\n"
		"           (to make them set secondary server IP address in their configs).\n\n"
		"In FreeBSD, you can obtain both user IP addresses/ports and IDs via sockstat(1)\n"
		"command, because daemon uses FD number as user ID.\n"
		: "For more help type %s -h\n",
		proctitle);
	exit(EX_USAGE);
}

/*** Main function ***/
int
main(int argc, char *argv[])
{
	struct accept_filter_arg afa;
	struct kevent kev[4];
	int ch, i, quiet = 0;
	struct sockaddr_in serv_addr;
	char *proctitle;

	/* Default values for some vars. */
	flood_threshold = DEF_FKILLTHRESH;
	ban_timeout = DEF_MAXPENALTY * flood_threshold;

	proctitle = argv[0];
	/* Parse command line options. */
	while ((ch = getopt(argc, argv, "a:c:df:qstu:h")) != -1) {
		switch (ch) {
		case 'd':
			debug += 1;
			break;
		case 'c':
			strlcpy(linkpath, optarg, sizeof(linkpath));
			break;
		case 'a':
			if (parse_addr(NULL, optarg))
				strlcpy(archpath, optarg, sizeof(archpath));
			else
				fprintf(stderr, "Invalid archiver address specified, ignoring.\n");
			break;
		case 'u':
			strlcpy(archlink, optarg, sizeof(archlink));
			break;
		case 'f':
			flood_threshold = atoi(optarg) < 3 ? 3 : atoi(optarg);
		case 't':
			ban_timeout = (atoi(optarg) < flood_threshold * DEF_MAXPENALTY) ?
				flood_threshold * DEF_MAXPENALTY : atoi(optarg);
			break;
		case 'q':
			quiet = 1;
			break;
		case 's':
			strict = 1;
			break;
		case 'h':
		case '?':
		default:
			usage(proctitle, ch);
		}
	}
	argc -= optind;
	argv += optind;

	/* XXX check non-opt arguments here in the future */

	/* Write all errors via syslog - it can handle stderr on startup too. */
	openlog(SYSLOG_IDENT, debug ? LOG_PERROR : LOG_NDELAY, LOG_USER);

	/* Open the listening socket. */
	bzero(&serv_addr, sizeof(struct sockaddr_in));

	if ((servsock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "can't create SEA server socket: %m");
		exit(EX_OSERR);
	}

	/* Fix the address already in use error */
	i = 1;
	if (setsockopt(servsock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(int)) == -1)
		syslog(LOG_WARNING, "setsockopt(SO_REUSEADDR) on listening socket failed: %m");

	memset(&serv_addr, 0, sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(SEA_PORT);

	if (bind(servsock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
		syslog(LOG_ERR, "bind() to port %d failed: %m", SEA_PORT);
		exit(EX_OSERR);
	}
	
	if (listen(servsock, 100) == -1) {
		syslog(LOG_ERR, "listen(): %m");
		exit(EX_OSERR);
	}

	/* Put socket into non-blocking mode */
	if (sock_nonblock(servsock) == -1) {
		syslog(LOG_ERR, "can't make listening socket nonblocking, exiting!");
		exit(EX_OSERR);
	}

	/*
	 * FreeBSD feature: we use accf_data(9) accept filter here, if it is
	 * kldload(8)'ed. This is only an example of usage, it is not critical
	 * for our program, so we ignore errors.
	 */
	bzero(&afa, sizeof(afa));
	strcpy(afa.af_name, "dataready");
	setsockopt(servsock, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa));

	/* Set up signal handlers. */
	init_sig();

	if (!debug) {
		if (quiet)
			setlogmask(LOG_UPTO(LOG_NOTICE));
		else
			setlogmask(LOG_UPTO(LOG_INFO));
		if (daemon(0, 0) < 0) {	/* Make program a daemon */
			syslog(LOG_ERR, "daemon() failed");
			exit(EX_OSERR);
		}
	}

	/* kqueue() descriptors are not inherited after fork(). */
	if ((kq = kqueue()) < 0)
		syslog(LOG_ERR, "kqueue() failed: %m");

	EV_SET(&kev[0], servsock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev[0], 1, NULL, 0, NULL) < 0) {
		syslog(LOG_ERR, "initial kevent: %m");
		exit(EX_OSERR);
	}

	/*
	 * KQ FEATURE: We use a timer (number 0) to schedule (in milliseconds)
	 * a periodic connection attempt timer. We don't do anything on error
	 * because archiver is optional facility. The timer is periodic so the
	 * reconnect_archiver() will check itself should it do the work or not.
	 * SEA SHIT: We also add timer 1 for pings, but the protocol is weird,
	 * clients ping server, so we can't do much and this is optional, too.
	 */
	EV_SET(&kev[0], 0, EVFILT_TIMER, EV_ADD, 0, ARCH_TIMEOUT*1000, &archq);
	EV_SET(&kev[1], 1, EVFILT_TIMER, EV_ADD, 0, TIMER_INTRVL*1000, NULL);
	if ((kevent(kq, kev, 2, NULL, 0, NULL) < 0))
		syslog(LOG_ERR, "adding timer kevent: %m");

	/*
	 * Connect archiver first time before clients. If it is descriptor
	 * number instead of address, use it one, and only one, time.
	 */
	archsock = parse_addr(&archaddr, archpath);
	if ((strlen(archpath) > 0) && (archsock < 0))
		connect_sock(&archsock, &archq, (struct sockaddr*)&archaddr);
	else if (archsock == 0)	/* avoid closing fd 0 by timer later */
		archsock = -1;
	else if (archsock > 0) {/* already opened, monitor writes */	
		EV_SET(&kev[0], archsock, EVFILT_WRITE, EV_ADD|EV_CLEAR, 0, 0, &archq);
		if ((kevent(kq, kev, 1, NULL, 0, NULL) < 0))
			syslog(LOG_ERR, "adding archiver write kevent: %m");
	}

	/*
	 * KQ FEATURE: We could process signals with kqueue(), too (see
	 * KQ FEATURE comment in event_loop() function), and we could put
	 * more then one event per time for processing. But additional
	 * signal aren't critical for our program, so we won't process errors
	 * here. Note that SIGUSR2 is marked SIG_IGN in init_sig() so that
	 * receiving it will not terminate process.
	 */
	EV_SET(&kev[0], SIGWINCH, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[1], SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[2], SIGUSR2, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[3], SIGINFO, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	if ((kevent(kq, kev, 4, NULL, 0, NULL) < 0))
		syslog(LOG_ERR, "adding signal kevent: %m");


	quit = 0;
	alarm_triggered = 0;
	cmdsig_triggered = 0;

	alarm(ALARM_TIME);
	
	while (quit == 0) {
		if (alarm_triggered) {
			process_timer();
			alarm_triggered = 0;
		}
		if (cmdsig_triggered) {
			admin_command(SIGUSR1);
			cmdsig_triggered = 0;
		}
		event_loop();
	}

	return 0;
}
