/*
 * $Id: yaz.h,v 1.54 2006/04/20 19:45:09 jsommers Exp $
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

#ifndef __YAZ_H__
#define __YAZ_H__

#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <vector>
#include <list>
#include <string>
#include <assert.h>
#include <limits.h>

#include "config.h"
#if HAVE_PCAP_H
#include <pcap.h>
#endif
#if HAVE_PTHREAD_H
#include <pthread.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif



static const int YAZBUFLEN = 4096;
static const int YAZTINYBUF = 32;
static const int YAZPCAPSNAPLEN = 64;
static const int YAZOSTIMINGSAMPLES = 100;

static const int MIN_SPACE = 40;
static const int MAX_SPACE = 1000;

static const int RETRY_LIMIT = 5;

static const unsigned short DEST_CTRL_PORT = 13979;
static const unsigned short DEST_PORT   = 13989;


#define PCTRL_INVALID       0x00000000

#define PCTRL_RST           0x0000DEAD
#define PCTRL_RST_ACK       0x0000BEEF
#define PCTRL_RST_NACK      0x0BADBEEF

// control message timeout
const int ctrl_msg_timeout = 10000;    // milliseconds (long!)
#if HAVE_PCAP_H
const int pcap_buffer_timeout = 10;    // milliseconds (arg to open_live())
const int pcap_wait_timeout = 5000;    // milliseconds (long!)
#endif

#ifndef timerclear
#define	timerclear(tvp)
        (tvp).tv_sec = 0; (tvp).tv_usec = 0;
#endif

#ifndef timersub
#define timersub(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)
#endif

#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
                if ((vvp)->tv_usec >= 1000000) {                        \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_usec -= 1000000;                      \
                }                                                       \
        } while (0)
#endif

struct YazCtrlMsg
{
    YazCtrlMsg(): m_code(PCTRL_INVALID), m_seq(0), m_len(0), m_reason(0) {}

    int m_code;
    int m_seq;
    int m_len;
    int m_reason;
};


struct YazRstResponse
{
    YazRstResponse() : m_app_mean(0), m_pcap_mean(0), m_ttl(0), m_nsamples(0), m_nlost(0) {}

    unsigned int m_app_mean;
    unsigned int m_pcap_mean;
    unsigned int m_ttl;
    unsigned int m_nsamples;
    unsigned int m_nlost;
};


struct ProbeStamp
{
    ProbeStamp(): m_stream(0), m_sequence(0), m_ttl(0)
        {
            m_ts.tv_sec = 0;
            m_ts.tv_usec = 0;
        }

    unsigned int m_stream;
    unsigned int m_sequence;
    unsigned int m_ttl;
    struct timeval m_ts;
};


struct YazPkt
{
    YazPkt() : m_stream(0), m_sequence(0) {}
    
    int m_stream;
    int m_sequence;
};


struct YazPcapCtrl
{
    YazPcapCtrl() : m_ok(0), m_mutex(0), m_tlist(0), m_dport(0)
#if HAVE_PCAP_H
    , m_pcap(0) 
#endif
    {}

    bool *m_ok;
    pthread_mutex_t *m_mutex;
    std::vector<ProbeStamp> *m_tlist;
    unsigned short m_dport;
#if HAVE_PCAP_H
    pcap_t *m_pcap;
#endif
};


class YazEndPt
{
public:
    YazEndPt() : m_verbose(0), m_ctrl_seq(0), m_ctrl_dest(DEST_CTRL_PORT), m_probe_dest(DEST_PORT), m_ctrl_sd(0), m_probe_sd(0), m_syscall_overhead(0), m_min_sleep(0)
#if HAVE_PCAP_H
               ,m_using_pcap(true), m_pcap_thread(0), m_running(0), m_pcap(0)
#endif
        {
            m_app_probes.clear();

#if HAVE_PCAP_H
            m_pcap_probes = new std::vector<ProbeStamp>();
            if (!m_pcap_probes)
            { 
                std::cerr << "!!couldn't allocate probe stamp vector" << std::endl;
                throw -1;
            }

            m_pcap_probes->clear();
            m_pcap_mutex = new pthread_mutex_t;

            if (!m_pcap_mutex || pthread_mutex_init(m_pcap_mutex, NULL) < 0)
            {
                std::cerr << "!!error initializing pcap mutex" << std::endl;
                throw -1;
            }

            m_pcap_filter_string = "";
            m_pcap_dev = "any";
            memset(m_pcap_err, 0, PCAP_ERRBUF_SIZE);

            m_pcap_thread = new pthread_t;
            m_running = new bool;
            *m_running = true;
#endif
        }

    virtual ~YazEndPt()
        {
#if HAVE_PCAP_H
            delete m_pcap_probes;
            delete m_pcap_mutex;
            delete m_pcap_thread;
            delete m_running;
#endif
        }
 
    virtual void run() = 0;
    virtual bool validate() = 0;

    void setVerbosity(int &i)  { m_verbose = i; }
    void setCtrlDest(unsigned short &s) { m_ctrl_dest = s; }
    void setProbeDest(unsigned short &s) { m_probe_dest = s; }
#if HAVE_PCAP_H
    void setPcapDev(std::string &s) { m_pcap_dev = s; }
#endif

protected:
    virtual void prepCtrl() = 0;
    virtual void prepProbe() = 0;
    virtual void cleanup() = 0;

#if HAVE_PCAP_H
    void prepPcap();
    void unprepPcap();
#endif

    void measureSyscallOverhead();
    void measureMinSleep();
    void getClockTick();
#if 0
    bool isValidStream(std::vector<ProbeStamp> *, int min_hint = 0);
#endif
    bool getSpacing(std::vector<ProbeStamp> *, float &, int &, int &, int min_hint = 0);
    bool checkTTL(std::vector<ProbeStamp> *, unsigned int &);

    int m_verbose;
    unsigned int m_ctrl_seq;
    unsigned short m_ctrl_dest;
    unsigned short m_probe_dest;
    int m_ctrl_sd;
    int m_probe_sd;

    std::vector<ProbeStamp> m_app_probes;
    int m_syscall_overhead;
    int m_min_sleep;

    int m_clock_tick;

#if HAVE_PCAP_H
    bool m_using_pcap;
    pthread_t *m_pcap_thread;
    bool *m_running;
    pcap_t *m_pcap;
    std::vector<ProbeStamp> *m_pcap_probes;
    pthread_mutex_t *m_pcap_mutex;
    std::string m_pcap_filter_string;
    char m_pcap_err[PCAP_ERRBUF_SIZE];
    std::string m_pcap_dev;
#endif
};


class YazSender : public YazEndPt
{
public:
    YazSender() : YazEndPt(), m_min_pkt_size(200), m_curr_pkt_size(1500), 
                  m_stream_length(50), m_target_spacing(MIN_SPACE), 
                  m_max_pkt_spacing(MAX_SPACE), m_nstreams(1),
                  m_inter_stream_spacing(20000), m_curr_stream(0),
                  m_resolution(1000000.0)
        {
            memset(&m_target_addr, 0, sizeof(struct in_addr));
            inet_pton(AF_INET, "127.0.0.1", &m_target_addr);
        }
    virtual ~YazSender() {}

    virtual void run();

    void setTarget(const char *ipaddr)
        {
            memset(&m_target_addr, 0, sizeof(struct in_addr));
            inet_pton(AF_INET, ipaddr, &m_target_addr);
        }

    bool checkTarget()
        {
            if (m_target_addr.s_addr == 0)
                return false; 
            return true;
        }

    virtual bool validate()
        {
            bool rv = true;
            rv = rv && checkTarget();
            if (m_verbose && !rv)
                std::cout << "## bad target address " << std::endl;
            rv = rv && (m_ctrl_dest > 1023);
            if (m_verbose && !rv)
                std::cout << "## bad dest control port " << std::endl;
            rv = rv && (m_probe_dest > 1023);
            if (m_verbose && !rv)
                std::cout << "## bad dest probe port" << std::endl;
            rv = rv && (m_min_pkt_size >= 28 && m_min_pkt_size <= 1500);
            if (m_verbose && !rv)
                std::cout << "## bad min pkt size" << std::endl;
            rv = rv && (m_stream_length > 1 && m_stream_length <= 250);
            if (m_verbose && !rv)
                std::cout << "## bad stream length" << std::endl;
            rv = rv && (m_nstreams >= 1 && m_nstreams <= 5);
            if (m_verbose && !rv)
                std::cout << "## bad number of streams per measurement" << std::endl;
            rv = rv && (m_inter_stream_spacing >= 10000 && m_inter_stream_spacing <= 1000000);
            if (m_verbose && !rv)
                std::cout << "## bad inter-stream spacing" << std::endl;

            measureSyscallOverhead();
            measureMinSleep();
            getClockTick();
            m_max_pkt_spacing = 1000000 / m_clock_tick / 2;
            m_inter_stream_spacing = std::max(m_inter_stream_spacing, m_clock_tick * 2);

            if (rv && m_verbose)
            {
                struct timeval tv;
                gettimeofday(&tv, 0);
                struct tm tms;
                localtime_r((const time_t *)&tv.tv_sec, &tms);
                char buf[YAZTINYBUF];
                memset(buf, 0, YAZTINYBUF);
                strftime(buf, YAZTINYBUF-1, "%Y-%m-%d %T", &tms);

                std::cout << "##yaz sender ok - started at " << buf << '.' << std::setw(6) << std::setfill('0') << tv.tv_usec << std::endl;
                inet_ntop(AF_INET, &m_target_addr, buf, YAZTINYBUF);
                std::cout << "##destination addr: " << buf << std::endl;
                std::cout << "##control port: " << m_ctrl_dest << std::endl;
                std::cout << "##probe port: " << m_probe_dest << std::endl;
                std::cout << "##min pkt size: " << m_min_pkt_size << std::endl;
                std::cout << "##stream length: " << m_stream_length << std::endl;
                std::cout << "##initial spacing: " << m_target_spacing << std::endl;
                std::cout << "##max spacing: " << m_max_pkt_spacing << std::endl;
                std::cout << "##resolution: " << m_resolution << std::endl;
                std::cout << "##streams: " << m_nstreams << std::endl;
                std::cout << "##inter-stream spacing: " << m_inter_stream_spacing << std::endl;
                if (m_verbose > 1)
                    std::cout << "##syscall overhead: " << m_syscall_overhead << std::endl;
            }

            if (!rv)
                std::cerr << "!!input validation failed" << std::endl;

            return (rv); 
        }

    void setMinPktSize(int &i) { m_min_pkt_size = i; }
    void setStreamLength(int &i) { m_stream_length = i; }
    void setMaxPktSpacing(int &i) { m_max_pkt_spacing = i; }
    void setStreams(int &i) { m_nstreams = i; }
    void setInterStreamSpacing(int &i) { m_inter_stream_spacing = i; }
    void setResolution(float &f) { m_resolution = f; }
    void setInitialSpacing(int &i) { m_target_spacing = i; }
    void setInitialPktSize(int &i) { m_curr_pkt_size = i; }

protected:
    virtual void prepCtrl();
    virtual void prepProbe();
    virtual void cleanup();

private:
    struct MeasurementBundle
    {
        MeasurementBundle() : m_local_app_mean(0), 
                              m_local_pcap_mean(0), 
                              m_remote_app_mean(0), 
                              m_remote_pcap_mean(0), 
                              m_local_ttl(0), m_remote_ttl(0),
                              m_local_nsamples(0), m_local_nlost(0),
                              m_remote_nsamples(0), m_remote_nlost(0)
            {
                timerclear(&m_start);
                timerclear(&m_end);
            }

        bool operator==(const MeasurementBundle &mb)
            {
                return (this->m_start.tv_sec == mb.m_start.tv_sec &&
                        this->m_start.tv_usec == mb.m_start.tv_usec);
            }

        bool operator<(const MeasurementBundle &mb)
            {
                return (timercmp(&this->m_start, &mb.m_start, <));
            }

        void reset()
            {
                timerclear(&m_start);
                timerclear(&m_end);

                m_local_app_mean =
                    m_local_pcap_mean =
                    m_remote_app_mean =
                    m_remote_pcap_mean = 0.0;

                m_local_ttl = m_remote_ttl = 0;

                m_local_nsamples =
                    m_local_nlost =
                    m_remote_nsamples =
                    m_remote_nlost = 0;
            }

        struct timeval m_start;
        struct timeval m_end;

        float m_local_app_mean;
        float m_local_pcap_mean;

        float m_remote_app_mean;
        float m_remote_pcap_mean;

        unsigned int m_local_ttl;
        unsigned int m_remote_ttl;

        unsigned int m_local_nsamples;
        unsigned int m_local_nlost;
        unsigned int m_remote_nsamples;
        unsigned int m_remote_nlost;
    };


    bool collectRemote(MeasurementBundle &);
    bool resetRemote();
    bool doOneMeasurementRound(std::list<MeasurementBundle> *);
    void sendStream();
    void sendProbe(char *, int, int, int);
    bool localSpacingConsistent(std::list<MeasurementBundle> *);
    bool isPathSame(std::list<MeasurementBundle> *);
    void coalesceMeasurements(std::list<MeasurementBundle> *, MeasurementBundle &);

    struct in_addr m_target_addr;
    int m_min_pkt_size;
    int m_curr_pkt_size;
    int m_stream_length;
    int m_target_spacing;
    int m_max_pkt_spacing;
    int m_nstreams;
    int m_inter_stream_spacing;
    int m_curr_stream;
    float m_resolution;
};


class YazReceiver : public YazEndPt
{
public:    
    YazReceiver(): YazEndPt() {}
    virtual ~YazReceiver() {}

    virtual void run();

    virtual bool validate()
        {
            bool rv = true;
            rv = rv && (m_ctrl_dest > 1023);
            rv = rv && (m_probe_dest > 1023);

            if (!rv)
            {
                std::cerr << "!!error validating specified receiver ports" << std::endl;
            }

            if (rv && m_verbose)
            {
                measureSyscallOverhead();
                getClockTick();

                struct timeval tv;
                gettimeofday(&tv, 0);
                struct tm tms;
                localtime_r((const time_t*)&tv.tv_sec, &tms);
                char buf[YAZTINYBUF];
                memset(buf, 0, YAZTINYBUF);
                strftime(buf, YAZTINYBUF-1, "%Y-%m-%d %T", &tms);

                std::cout << "##yaz receiver ok - started at " << buf << '.' << std::setw(6) << std::setfill('0') << tv.tv_usec << std::endl;
                std::cout << "##control port: " << m_ctrl_dest << std::endl;
                std::cout << "##probe port: " << m_probe_dest << std::endl;

                if (m_verbose > 1)
                    std::cout << "##syscall overhead: " << m_syscall_overhead << std::endl;
            }

            return (rv);
        }

protected:
    virtual void prepCtrl();
    virtual void prepProbe();
    virtual void cleanup();

private:
    void getConnection(int &, bool &);
    void processControlMessage(int, bool &);
    void processProbe();
};


#endif // __YAZ_H__
