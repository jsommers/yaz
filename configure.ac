# 
# $Id: configure.ac,v 1.23 2006/04/20 19:51:26 jsommers Exp $
#

AC_PREREQ(2.57)
AC_INIT(yaz, 0.1, jsommers@cs.wisc.edu)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([.])
AC_REVISION( $Id: configure.ac,v 1.23 2006/04/20 19:51:26 jsommers Exp $ )

AC_ARG_ENABLE([pcap], AS_HELP_STRING([--enable-pcap],[open pcap device (for timestamps)]), AC_SUBST(USE_PCAP, 1), AC_SUBST(USE_PCAP, 0))

# we don't really do any installation at all of yaz. 
AC_PREFIX_DEFAULT([/usr/local])

AC_LANG(C++)

CXXFLAGS="-g"
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL


#
# need to do this early on, because we find the dlcompat libraries
# for macos-x in /sw and later checks depend on that...
#
AC_CANONICAL_SYSTEM

case "$target" in
    *solaris*)
	if test "$CXX" = "CC"
	then
		CXXFLAGS="$CXXFLAGS +w -mt" ;
	fi ;
	LIBS="$LIBS -mt -lpthread -lthread -lpcap -lsocket -lnsl" ;;
    *apple-darwin6*)
	CXXFLAGS="$CXXFLAGS -Wmost -no-cpp-precomp -fno-common" ;
	;;
    *apple-darwin7*)
	CXXFLAGS="$CXXFLAGS -Wmost";
	;; 
    *apple-darwin8*)
	CXXFLAGS="$CXXFLAGS -Wmost";
	;; 
    *linux*)
        CXXFLAGS="$CXXFLAGS -Wall -pthread" ;
        CPPFLAGS="$CPPFLAGS -I/usr/include/pcap -D_REENTRANT" ;
	;;
    *dragonfly*)
	CXXFLAGS="$CXXFLAGS -Wall -pthread" ;
        CPPFLAGS="$CPPFLAGS -D_THREAD_SAFE -D_REENTRANT" ;
	;;
    *freebsd*)
	CXXFLAGS="$CXXFLAGS -Wall -pthread" ;
	LDFLAGS="-pthread" ;
        CPPFLAGS="$CPPFLAGS -D_THREAD_SAFE -D_REENTRANT" ;
	;;
    *)
	echo "unsupported platform - good luck!"
esac

AC_CHECK_HEADERS([sys/socket.h])


if test "$USE_PCAP" = "1" ;
then
    AC_CHECK_HEADERS([pcap.h])
    AC_CHECK_LIB([pcap], [pcap_open_live],,[AC_MSG_ERROR("can't find libpcap")])

    AC_MSG_CHECKING([for pcap_setnonblock()])
    AC_COMPILE_IFELSE(
    [#include <pcap.h>
    int main(int argc, char **argv)
    {
        pcap_t *p = 0;
        char ebuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(p, 1, ebuf);
    }
    ], [AC_DEFINE(HAVE_PCAP_SETNONBLOCK,1)
        AC_MSG_RESULT([yes])], 
       [AC_DEFINE(HAVE_PCAP_SETNONBLOCK,0)    
        AC_MSG_RESULT([no])])
    
    AC_MSG_CHECKING([for pcap immediate mode (BIOCIMMEDIATE)])
    AC_COMPILE_IFELSE(
    [#include <sys/ioctl.h>
     #include <pcap.h>
    int main(int argc, char **argv)
    {
        unsigned long ioc = BIOCIMMEDIATE;
    }
    ], [AC_DEFINE(HAVE_PCAP_BIOCIMMEDIATE)
        AC_MSG_RESULT([yes])], 
       AC_MSG_RESULT([no])) ;
fi

    
AC_CHECK_HEADERS([float.h])
AC_CHECK_HEADERS([pthread.h])
AC_CHECK_LIB([thread], [thr_create],,)
AC_CHECK_LIB([pthread], [pthread_create],,)
AC_CHECK_LIB([c_r], [pthread_create],,)
AC_CHECK_TYPE(socklen_t, AC_DEFINE(SOCKLEN_T,socklen_t), AC_DEFINE(SOCKLEN_T,int), 
[#if HAVE_SYS_SOCKET_H
# include <sys/types.h>
# include <sys/socket.h>
# endif])
    
AC_CHECK_HEADERS([sched.h])
AC_CHECK_FUNCS(sched_setscheduler)

AC_CHECK_FUNCS(sysctlbyname)
AC_CHECK_FUNCS(sysconf)
AC_CHECK_HEADERS([sys/param.h])

AC_CONFIG_FILES([Makefile])
AC_SUBST(TEMPLATEDIR)
AC_SUBST(SOCKLEN_T)
AC_SUBST(HAVE_PCAP_SETNONBLOCK)
AC_SUBST(HAVE_PCAP_BIOCIMMEDIATE)
AC_SUBST(HAVE_SCHED_SETSCHEDULER)
AC_OUTPUT

