/*
 * $Id: yaz.cc,v 1.52 2005/12/09 16:33:51 jsommers Exp $
 */

/*
 * Copyright (c) 2005  Joel Sommers.  All rights reserved.
 *
 * This file is part of yaz, an end-to-end available bandwidth
 * measurement tool.
 *
 * Yaz is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Yaz is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Yaz; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "yaz.h"

#include <unistd.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <math.h>

#if HAVE_SYSCTLBYNAME
#include <sys/sysctl.h>
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <list>

#if HAVE_PCAP_H
static int offset = 0;

static int get_offset(int dltype)
{
    int offset = 0;
    switch (dltype)
    {
    case DLT_NULL:
        offset = 0;
        break;
    case DLT_EN10MB:
        offset = 14;
        break;
    case DLT_LOOP:
    case DLT_RAW: 
    case DLT_PPP_SERIAL:
        offset = 6;
        break;
    case DLT_C_HDLC:
        offset = 4;
        break;
    case DLT_ATM_RFC1483:
        offset = 8;
        break;
    default:
        std::cerr << "unknown data link type: offset will be wrong." << std::endl;
        break;
    }
    return offset;
}


void pcap_callback(u_char *arg, const pcap_pkthdr *ph, const u_char *pkt)
{
    void *varg = (void *)arg;
    YazPcapCtrl *ppc = static_cast<YazPcapCtrl*>(varg);

    struct ip *iph = (struct ip *)(pkt + offset);
    YazPkt *pp = (YazPkt *)(pkt + offset + iph->ip_hl * 4 + sizeof(struct udphdr));

    ProbeStamp ps;
    ps.m_ts = ph->ts;
    ps.m_ttl = iph->ip_ttl;
    ps.m_stream = ntohl(pp->m_stream);
    ps.m_sequence = ntohl(pp->m_sequence);
        
    pthread_mutex_lock(ppc->m_mutex);
    (ppc->m_tlist)->push_back(ps);
    pthread_mutex_unlock(ppc->m_mutex);
}


extern "C"
{
    void *pcap_thread_entry(void *arg)
    {
        YazPcapCtrl *ppc = static_cast<YazPcapCtrl*>(arg);
        if (!ppc)
        {
            std::cerr << "!!error getting arguments in pcap thread" << std::endl;
            throw -1;
        }

        offset = get_offset(pcap_datalink(ppc->m_pcap));

#if HAVE_PCAP_SETNONBLOCK
        char ebuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(ppc->m_pcap, 1, ebuf);
#endif

        std::cerr << "!!pcap initialized" << std::endl;

        int pcapfd = pcap_fileno(ppc->m_pcap);
        pollfd pfd;
 
        while (*(ppc->m_ok))
        {
            int npkt = pcap_dispatch(ppc->m_pcap, -1, pcap_callback, (u_char*)arg);
            if (npkt < 0)
                std::cerr << "error in pcap dispatch: " << pcap_geterr(ppc->m_pcap) << std::endl;

            pfd.fd = pcapfd; 
            pfd.events = POLLIN;
            pfd.revents = 0;
            int n = poll(&pfd, 1, 1000);
            if (n < 0)
                std::cerr << "error in poll in pcap loop: " << errno << '/' << strerror(errno) << std::endl;
        }

        return (0);
    }
}


void YazEndPt::prepPcap()
{
    assert (m_pcap_filter_string != "");

    // only attempt to configure pcap if an interface
    // has been specified.
    if (m_pcap_dev == "")
    {
        m_using_pcap = false;
        m_pcap = 0;
        return;
    }

    int snaplen = YAZPCAPSNAPLEN;
    int tmo = 0;
    m_pcap = pcap_open_live((char *)m_pcap_dev.c_str(), snaplen, 1, tmo, m_pcap_err);

    if (!m_pcap)
    {
        std::cerr << "!!pcap initialization failed: " << m_pcap_err << std::endl;
        std::cerr << "!!continuing without pcap." << std::endl;
        m_using_pcap = false;
        m_pcap = 0;
        return;
    }

#if HAVE_PCAP_BIOCIMMEDIATE
    int imm = 1;
    if ( ioctl(pcap_fileno(m_pcap), BIOCIMMEDIATE, &imm) < 0 ) 
        std::cerr << "unable to set wire-immediate mode" << std::endl;
#endif

    struct bpf_program code;
    bpf_u_int32 netmask = 0;
    char buf[YAZBUFLEN];
    memset(buf, 0, YAZBUFLEN);
    strncpy(buf, m_pcap_filter_string.c_str(), YAZBUFLEN-1);

    if (pcap_compile(m_pcap, &code, buf, 1, netmask) < 0)
    {
        std::cerr << "!!pcap filter string compilation failed: " << pcap_geterr(m_pcap) << std::endl;
        throw -1;
    }

    if (pcap_setfilter(m_pcap, &code) < 0) 
    {
        std::cerr << "!!failed to set pcap filter: " << pcap_geterr(m_pcap) << std::endl;
        throw -1;
    }

    YazPcapCtrl *m_ppc = new YazPcapCtrl();
    m_ppc->m_ok = m_running;
    m_ppc->m_mutex = m_pcap_mutex;
    m_ppc->m_tlist = m_pcap_probes;
    m_ppc->m_pcap = m_pcap;
    m_ppc->m_dport = m_probe_dest;

    if (pthread_create(m_pcap_thread, NULL, pcap_thread_entry, m_ppc) != 0)
    {
        std::cerr << "!!error spawning pcap thread: " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    }
}


void YazEndPt::unprepPcap()
{
    if (m_pcap)
        pcap_close(m_pcap);
    m_pcap = 0;
}
#endif // HAVE_PCAP_H


void YazEndPt::measureSyscallOverhead()
{
    struct timeval tvli[YAZOSTIMINGSAMPLES];
    for (int i = 0; i < YAZOSTIMINGSAMPLES; ++i)
        gettimeofday(&tvli[i], 0);

    double diffsum = 0.0;
    struct timeval diff = {0,0};
    std::list<double> diffli;

    for (int i = 1; i < YAZOSTIMINGSAMPLES; ++i)
    {
        timersub(&tvli[i], &tvli[i-1], &diff);
        double d =  diff.tv_sec * 1000000.0 + double(diff.tv_usec);
        diffsum += d;
        diffli.push_back(d);
    }
    diffli.sort();

    std::list<double>::iterator it = diffli.begin();
    for (int i = 0; i < YAZOSTIMINGSAMPLES/2; ++i, ++it) ;
    double median = *it;
    
    double sco = diffsum / (YAZOSTIMINGSAMPLES - 1);
    if (m_verbose)
    {
        std::cout << "##syscall overhead mean: " << sco << " microseconds" << std::endl;
        std::cout << "##syscall overhead median: " << median << " microseconds" << std::endl;
    }
    m_syscall_overhead = int(sco);
}


void YazEndPt::measureMinSleep()
{
    struct timeval ts[YAZOSTIMINGSAMPLES];
    gettimeofday(&ts[0], 0);
    for (int i = 1; i < YAZOSTIMINGSAMPLES; ++i)
    {
        usleep(1);
        gettimeofday(&ts[i], 0);
    }

    double usecsum = 0.0;
    double usecsumsq = 0.0;
    int imax = 0;
    struct timeval diff = {0,0};
    std::list<double> diffli;
    for (int i = 1; i < YAZOSTIMINGSAMPLES; ++i)
    {
        timersub(&ts[i], &ts[i-1], &diff);
        double usecs = diff.tv_sec * 1000000.0 + double(diff.tv_usec);
        usecsum += usecs;
        usecsumsq += pow(usecs, 2.0);
        imax = std::max(imax, int(diff.tv_sec * 1000000 + diff.tv_usec)); 
        diffli.push_back(diff.tv_sec * 1000000.0 + double(diff.tv_usec));
    }
    diffli.sort();
    std::list<double>::iterator it = diffli.begin();
    for (int i = 0; i < YAZOSTIMINGSAMPLES/2; ++i, ++it) ;
    double median = *it;
    double mean = usecsum / double(YAZOSTIMINGSAMPLES - 1); 
    double stdev = sqrt((usecsumsq * (YAZOSTIMINGSAMPLES - 1) - pow(usecsum,2.0)) / (double(YAZOSTIMINGSAMPLES - 2) * double(YAZOSTIMINGSAMPLES - 1)));
     

    // m_min_sleep is the minimun amount of time (usecs) that we'll attempt
    // to sleep.  otherwise, we spin-wait.
    m_min_sleep = std::max(0, int(mean + (3 * stdev)));

    if (m_verbose)
    {
        std::cout << "##mean sleep: " << mean << " microseconds" << std::endl;
        std::cout << "##stdev sleep: " << stdev << " microseconds" << std::endl;
        std::cout << "##median sleep: " << median << " microseconds" << std::endl;
        std::cout << "##max sleep: " << imax << " microseconds" << std::endl;
    }
}


#if 0
bool YazEndPt::isValidStream(std::vector<ProbeStamp> *vps, int min_hint)
{
    bool rv = true;
    float microthresh = 1000000.0 / m_clock_tick / 2.0;
    if (min_hint != 0)
        microthresh = std::min(microthresh, float(min_hint));
    struct timeval diff;

    for (size_t i = 1; i < vps->size(); ++i)
    {
        timersub(&(*vps)[i].m_ts, &(*vps)[i-1].m_ts, &diff);
        float micros = diff.tv_sec * 1000000.0 + float(diff.tv_usec);
        if (micros > microthresh)
            return false;
    }
    return (rv);
}
#endif


bool YazEndPt::getSpacing(std::vector<ProbeStamp> *vps,
                          float &mean, int &nused, int &nlost, int min_hint)
{
    bool rv = true;
    float microthresh = 1000000.0 / m_clock_tick;
    if (min_hint != 0)
        microthresh = std::min(microthresh, float(min_hint));
    mean = 0.0;
    nused = 0;
    nlost = 0;

    if (m_verbose > 1)
        std::cout << "##spc";

    std::list<float> spacings;
    for (size_t i = 1; i < vps->size() && rv; ++i)
    {
        bool lost = false;
        if ((*vps)[i].m_sequence != ((*vps)[i-1].m_sequence + 1))
        {
            lost = true;
            // only bail out if pkts were reordered, not if something
            // was lost.  if lost pkts, then egress spacing is (almost
            // by definition) larger than ingress, so this will cause
            // us to back off, as we want anyway.
        
            rv = ((*vps)[i].m_sequence > (*vps)[i-1].m_sequence);
            if (m_verbose)
                std::cout << "!! lost or reordered <" << (*vps)[i-1].m_sequence << "," << (*vps)[i].m_sequence << ">" << std::endl;
            nlost += (*vps)[i].m_sequence - (*vps)[i-1].m_sequence;
        }
        
        struct timeval diff;
        timersub(&(*vps)[i].m_ts, &(*vps)[i-1].m_ts, &diff);
        float m = diff.tv_sec * 1000000.0 + float(diff.tv_usec);
        if (m_verbose > 1)
            std::cout << ":" << int(m);

        // definitely include lost
        // if (lost || (m > MIN_SPACE && m < microthresh)) // FIXME min spa???
        if (lost || m < microthresh) // FIXME min spa???
            spacings.push_back(m);
    }


    float sum = 0, n = 0;
    for (std::list<float>::const_iterator iter = spacings.begin();
         iter != spacings.end(); ++iter)
    {
        sum += *iter;
        n += 1;
    }
     
    nused = int(n);

    if (rv && n > 1)
    {
        mean = sum / n;
    }
    else if (rv && n == 0)
    {
        mean = 0;
    }

    if (m_verbose > 1)
        std::cout << " nspacings: " << nused << " nlost: " << nlost << " mean: " << mean << std::endl;

    return (rv);
}


bool YazEndPt::checkTTL(std::vector<ProbeStamp> *vps, unsigned int &ttl)
{
    if (vps->size() == 0)
        return true;

    ttl = (*vps)[0].m_ttl;
    bool rv = true;

    // just make sure that ttl didn't change over course of
    // measurement period.  return true if it didn't, and
    // set ttl to the number of hops.
    for (size_t i = 1; i < vps->size() && rv; ++i)
    {
        rv = (ttl == (*vps)[i].m_ttl);
    }
    return (rv);
}


void YazEndPt::getClockTick()
{
    // try a few methods --- default to 100 ticks per second if all
    // fail.
    const int DEFAULT_HZ = 100;

#if HAVE_SYSCTLBYNAME

    // common on BSD systems 
    struct clockinfo ci;
    size_t cisize = sizeof(ci);
    int rv = sysctlbyname("kern.clockrate", &ci, &cisize, 0, 0);
    if (rv == 0)
        m_clock_tick = ci.hz;
    else
        m_clock_tick = DEFAULT_HZ;

#elif HAVE_SYSCONF

    // pretty common interface - try this first
    m_clock_tick = int(sysconf(_SC_CLK_TCK));

#elif HAVE_PARAM_H
#ifdef HZ

    // on linux and solaris, maybe others
    m_clock_tick = int(HZ);

#else

    // whatever, we tried.
    m_clock_tick = DEFAULT_HZ;

#endif
#endif 

    if (m_verbose)
        std::cout << "## clock tick (HZ): " << m_clock_tick << std::endl;
}

