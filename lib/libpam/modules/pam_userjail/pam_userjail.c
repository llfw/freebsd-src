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
	int inherit = JAIL_SYS_INHERIT;
	int persist = 1;
	size_t nvecs = 0;
#define IOV(x) { __DECONST(char *, x), sizeof(x) }
	struct iovec jailv[] = {
		IOV("path"),	IOV("/"),
		IOV("persist"),	{ &persist, sizeof(persist) },
		IOV("host"),	{ &inherit, sizeof(inherit) },
		IOV("ip4"),	{ &inherit, sizeof(inherit) },
		IOV("ip6"),	{ &inherit, sizeof(inherit) },
		IOV("name"),	{ jailname, sizeof(jailname) },
		IOV("errmsg"),	IOV(errmsg),
	};
#undef IOV


	if (argc) {
		syslog(LOG_ERR, "pam_userjail: unknown argument \"%s\"",
			argv[0]);
		retval = PAM_SERVICE_ERR;
		goto out;
	}

	(void)pamh;
	(void)flags;

	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
		goto out;

	if ((pwd = getpwnam(user)) == NULL) {
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

	snprintf(jailname, sizeof(jailname), "usrj-uid-%" PRId64,
		 (int64_t)pwd->pw_uid);

	nvecs = sizeof(jailv) / sizeof(*jailv);
	retval = jail_set(jailv, nvecs, JAIL_CREATE | JAIL_ATTACH);

	if (retval == -1 && errno == EEXIST) {
		printf("creating the jail failed, updating instead\n");
		retval = jail_set(jailv + 10, nvecs - 10, JAIL_UPDATE | JAIL_ATTACH);
	}

	printf("pam_userjail is here, jail=[%s], i am %d\n", jailname, (int)getuid());
	for (size_t i = 0; i < sizeof(jailv) / sizeof(struct iovec); ++i)
		printf("jail param: [%s] %d\n", (const char *)jailv[i].iov_base, (int)jailv[i].iov_len);

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
	return PAM_SUCCESS;
}

PAM_MODULE_ENTRY("pam_userjail");
