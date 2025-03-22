/*
 * This source code is released into the public domain.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/jail.h>

#include <login_cap.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <inttypes.h>
#include <jail.h>
#include <errno.h>

#include <libutil.h>

#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>

typedef struct {
	struct iovec *iovs;
	size_t niovs;
} iovlist_t;

static iovlist_t *
iovlist_create(void)
{
	iovlist_t *ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return (NULL);

	return (ret);
}

static struct iovec *
iovlist_iovs(iovlist_t *iovl)
{
	return (iovl->iovs);
}

static size_t
iovlist_len(iovlist_t *iovl)
{
	return (iovl->niovs);
}

static void
iovlist_free(iovlist_t *iovl)
{
	free(iovl->iovs);
	free(iovl);
}

static int
iovlist_add(iovlist_t *iovl, char const *name, void const *value, size_t len)
{
	struct iovec *iovs = NULL;

	iovs = realloc(iovl->iovs, sizeof(struct iovec) * (iovl->niovs + 2));
	if (iovs == NULL)
		return (-1);

	iovl->iovs = iovs;
	iovl->iovs[iovl->niovs].iov_base = __DECONST(char *, name);
	iovl->iovs[iovl->niovs].iov_len = strlen(name) + 1;
	iovl->iovs[iovl->niovs + 1].iov_base = __DECONST(void *, value);
	iovl->iovs[iovl->niovs + 1].iov_len = len;
	iovl->niovs += 2;

	return (0);
}

static int
iovlist_add_string(iovlist_t *iovl, char const *name, char const *value)
{
	return (iovlist_add(iovl, name, value, strlen(value) + 1));
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	int retval = 0;
	struct passwd *pwd = NULL;
	const char *user = NULL;
	login_cap_t *lc = NULL;
	char jailname[sizeof("usrj-uid-9223372036854775808")] = {};
	char errmsg[JAIL_ERRMSGLEN + 1] = {};
	int inherit = JAIL_SYS_INHERIT, new = JAIL_SYS_NEW;
	int persist = 1;
	iovlist_t *iovlist = NULL;
	size_t update_skip = 0;

	if (argc) {
		syslog(LOG_ERR, "pam_userjail: unknown argument \"%s\"",
			argv[0]);
		retval = PAM_SERVICE_ERR;
		goto out;
	}

	(void)flags;

	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_userjail: pam_get_user() failed");
		goto out;
	}

	if ((pwd = getpwnam(user)) == NULL) {
		syslog(LOG_ERR, "pam_userjail: user unknown: %s", user);
		retval = PAM_USER_UNKNOWN;
		goto out;
	}

	if ((lc = login_getpwclass(pwd)) == NULL) {
		syslog(LOG_ERR, "pam_userjail: login_getpwclass() "
		       "failed for user \"%s\"",
			pwd->pw_name);
		retval = PAM_SERVICE_ERR;
		goto out;
	}

	if (login_getcapbool(lc, "userjail", 0) == 0) {
		retval = PAM_SUCCESS;
		goto out;
	}

	if ((iovlist = iovlist_create()) == NULL) {
		syslog(LOG_ERR, "pam_userjail: out of memory");
		retval = PAM_SERVICE_ERR;
		goto out;
	}

	/* These are the values we want to skip when updating. */
	iovlist_add_string(iovlist, "path", "/");
	++update_skip;

	iovlist_add(iovlist, "persist", &persist, sizeof(persist));
	++update_skip;

	iovlist_add(iovlist, "host", &inherit, sizeof(inherit));
	++update_skip;

	if (login_getcapbool(lc, "userjail.net4", 0)
	    || login_getcapbool(lc, "userjail.net_basic", 0)) {
		iovlist_add(iovlist, "ip4", &inherit, sizeof(inherit));
		++update_skip;
	}

	if (login_getcapbool(lc, "userjail.net6", 0)
	    || login_getcapbool(lc, "userjail.net_basic", 0)) {
		iovlist_add(iovlist, "ip6", &inherit, sizeof(inherit));
		++update_skip;
	}

	if (login_getcapbool(lc, "userjail.sysvipc", 0)) {
		iovlist_add(iovlist, "sysvmsg", &inherit, sizeof(inherit));
		iovlist_add(iovlist, "sysvsem", &inherit, sizeof(inherit));
		iovlist_add(iovlist, "sysvshm", &inherit, sizeof(inherit));
		update_skip += 3;
	} else if (login_getcapbool(lc, "userjail.sysvipcnew", 0)) {
		iovlist_add(iovlist, "sysvmsg", &new, sizeof(new));
		iovlist_add(iovlist, "sysvsem", &new, sizeof(new));
		iovlist_add(iovlist, "sysvshm", &new, sizeof(new));
		update_skip += 3;
	}

	/* These values should always be passed */

	if (login_getcapbool(lc, "userjail.net_raw", 0)
	    || login_getcapbool(lc, "userjail.net_all", 0))
		iovlist_add(iovlist, "allow.raw_sockets", NULL, 0);

	if (login_getcapbool(lc, "userjail.net_all", 0))
		iovlist_add(iovlist, "allow.socket_af", NULL, 0);

	if (login_getcapbool(lc, "userjail.mlock", 0))
		iovlist_add(iovlist, "allow.mlock", NULL, 0);

	iovlist_add(iovlist, "allow.noset_hostname", NULL, 0);

	snprintf(jailname, sizeof(jailname), "usrj-uid-%" PRId64,
		 (int64_t)pwd->pw_uid);
	iovlist_add_string(iovlist, "name", jailname);

	iovlist_add(iovlist, "errmsg", errmsg, sizeof(errmsg));

	/*
	 * Try to create the jail first; if it already exists, update/attach
	 * instead.
	 */
	retval = jail_set(iovlist_iovs(iovlist), iovlist_len(iovlist),
			  JAIL_CREATE | JAIL_ATTACH);

	if (retval < 0 && errno == EEXIST)
		retval = jail_set(iovlist_iovs(iovlist) + (update_skip * 2),
				  iovlist_len(iovlist) - (update_skip * 2),
				  JAIL_UPDATE | JAIL_ATTACH);

	if (retval < 0) {
		syslog(LOG_ERR, "pam_userjail: jail_set failed: %m (%s)",
		       errmsg);
		retval = PAM_SERVICE_ERR;
		goto out;
	}

	retval = PAM_SUCCESS;

out:
	if (lc)
		login_close(lc);

	if (iovlist)
		iovlist_free(iovlist);

	return (retval);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	if (argc) {
		syslog(LOG_ERR, "pam_userjail: unknown argument \"%s\"",
			argv[0]);
		return (PAM_SERVICE_ERR);
	}

	(void)pamh;
	(void)flags;
	return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_userjail");
