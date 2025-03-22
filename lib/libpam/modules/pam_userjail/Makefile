# This source code is released into the public domain.

.include <src.opts.mk>
.include <bsd.init.mk>

PACKAGE=	runtime

LIB=	pam_userjail
SRCS=	pam_userjail.c
MAN=	pam_userjail.8

LIBADD+=	util jail

.include <bsd.lib.mk>
