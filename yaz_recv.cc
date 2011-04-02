/*
 * $Id: yaz_recv.cc,v 1.28 2005/12/12 22:41:05 jsommers Exp $
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
#if HAVE_PCAP_H
#include <sstream>
#endif


void YazReceiver::prepCtrl()
{
    m_ctrl_sd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_ctrl_sd < 0)
    {
        std::cerr << "!!socket(): " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    } 

    int opt = 1;
    if (setsockopt(m_ctrl_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        std::cerr << "!!setsockopt(): " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    }

    struct sockaddr_in ctrl_sin;
    memset(&ctrl_sin, 0, sizeof(struct sockaddr_in));
    ctrl_sin.sin_family = AF_INET;
    ctrl_sin.sin_port = htons(DEST_CTRL_PORT);
    if (bind(m_ctrl_sd, (const struct sockaddr*)&ctrl_sin, sizeof(struct sockaddr_in)) < 0)
    {
        std::cerr << "!!bind(): " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    } 

    if (listen(m_ctrl_sd, 2) < 0)
    {
        std::cerr << "!!listen(): " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    } 

    if (m_verbose)
    {
        struct sockaddr_in sinname;
        memset(&sinname, 0, sizeof(sockaddr_in));
        SOCKLEN_T sinlen = sizeof(sinname);
        if (getsockname(m_ctrl_sd, (struct sockaddr *)&sinname, &sinlen) < 0)
        {
            std::cerr << "!! (non-fatal) error getting socket name: " << errno << '/' << strerror(errno) << std::endl;
        }

        char buffer[YAZBUFLEN];
        memset(&buffer[0], 0, YAZBUFLEN);
        inet_ntop(AF_INET, &sinname.sin_addr, buffer, 1023);

        std::cout << "##receiver control listening at " << buffer << " tcp/" << DEST_CTRL_PORT << std::endl;
    }
}


void YazReceiver::prepProbe()
{
    m_probe_sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_probe_sd < 0)
    {
        std::cerr << "!!socket(): " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    } 

    struct sockaddr_in probe_sin;
    memset(&probe_sin, 0, sizeof(struct sockaddr_in));
    probe_sin.sin_family = AF_INET;
    probe_sin.sin_port = htons(DEST_PORT);
    if (bind(m_probe_sd, (const struct sockaddr*)&probe_sin, sizeof(struct sockaddr_in)) < 0)
    {
        std::cerr << "!!bind(): " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    } 

    if (m_verbose)
    {
        struct sockaddr_in sinname;
        memset(&sinname, 0, sizeof(sockaddr_in));
        SOCKLEN_T sinlen = sizeof(sinname);
        if (getsockname(m_probe_sd, (struct sockaddr *)&sinname, &sinlen) < 0)
        {
            std::cerr << "!! (non-fatal) error getting socket name: " << errno << '/' << strerror(errno) << std::endl;
        }

        char buffer[YAZBUFLEN];
        memset(&buffer[0], 0, YAZBUFLEN);
        inet_ntop(AF_INET, &sinname.sin_addr, buffer, YAZBUFLEN-1);
        std::cout << "##probe sink at " << buffer << " udp/" << DEST_PORT << std::endl;
    }
}


void YazReceiver::cleanup()
{
    close (m_probe_sd);
    close (m_ctrl_sd);

#if HAVE_PCAP_H
    unprepPcap();
#endif
}


void YazReceiver::getConnection(int &csd, bool &connected)
{
    bool rv = false;

    pollfd pfd = {m_ctrl_sd, POLLIN, 0};
    int n = poll(&pfd, 1, 1000);

    if (n < 0)
    {
        std::cerr << "error on poll: " << errno << '/' << strerror(errno) << std::endl;
        cleanup();
        throw -1;
    }
    else if (n == 1 && (pfd.revents & POLLIN))
    {
        struct sockaddr_in csin;
        SOCKLEN_T sinlen = sizeof(struct sockaddr_in);
        int sd = accept(m_ctrl_sd, (struct sockaddr *)&csin, &sinlen);
        if (sd <= 0)
        {
            std::cerr << "error on accept: " << errno << '/' << strerror(errno) << std::endl;
            cleanup();
            throw -1;
        } 
        else
        {
            rv = true;
            csd = sd;
            connected = true;
        } 
    }
}


void YazReceiver::run()
{
    bool connected = false;
    int csd = 0;

#if HAVE_PCAP_H
    std::ostringstream ostr;
    ostr << "udp and dst port " << m_probe_dest;
    m_pcap_filter_string = ostr.str();
#endif

    try
    {
        prepCtrl();
        prepProbe();
#if HAVE_PCAP_H
        prepPcap();
#endif

        while (1)
        {
            csd = 0;
            connected = false;
            while (!connected)
            {
                getConnection(csd, connected); 
                if (connected && m_verbose)
                    std::cout << "!! got connection" << std::endl;
            }

            pollfd pfd[2];
            int npfd = 0;
            while (connected)
            {
                memset(pfd, 0, sizeof(pollfd) * 2);
           
                pfd[0].fd = csd;
                pfd[0].events = POLLIN;
                pfd[0].revents = 0;

                pfd[1].fd = m_probe_sd;
                pfd[1].events = POLLIN;
                pfd[1].revents = 0;

                npfd = 2;
                int rv = poll(&pfd[0], npfd, 0);
                if (rv == -1)
                {
                    std::cerr << "error in poll(): " << errno << '/' << strerror(errno) << std::endl;
                    cleanup();
                    throw -1;
                }

                if (rv > 0)
                {
                    if (pfd[1].revents & POLLIN)
                    {
                        processProbe();
                    }
                    else if (pfd[0].revents & POLLIN)
                    {
                        processControlMessage(csd, connected);
                    }

                }
            } 
        }
    }
    catch (...)
    {
        std::cout << "!!fatal error - receiver stopping" << std::endl;
    }

#if HAVE_PCAP_H
    *m_running = false;
    if (m_using_pcap && *m_pcap_thread)
        pthread_cancel(*m_pcap_thread);
#endif
    return;
}


void YazReceiver::processControlMessage(int sd, bool &connected)
{
    YazCtrlMsg pmsg;
    char *buffer = 0;
    YazRstResponse *yrr = 0;

    int remain = sizeof(YazCtrlMsg);
    int offset = 0; 
    while (remain > 0)
    {
        int n = recv(sd, ((char*)&pmsg)+offset, remain, 0);
        if (n < 0)
        {
            std::cerr << "!!error on recv() for control message: " << errno << '/' << strerror(errno) << std::endl;
            throw -1;
        }

        if (n == 0)
        {
            close(sd);
            connected = false;
            return;
        }
   
        
        remain -= n;
        offset += n;
    }
    
    m_ctrl_seq = ntohl(pmsg.m_seq);
    assert (ntohl(pmsg.m_len) == 0);

    if (m_verbose > 3)
        std::cout << "## received " << offset << " byte control message" << std::endl;

    switch (ntohl(pmsg.m_code))
    {
    case PCTRL_RST:
        {
            if (m_verbose > 1)
                std::cout << "## received RST control message" << std::endl;
            assert (pmsg.m_len == 0);
            yrr = new YazRstResponse();
            buffer = (char *)yrr;

            pmsg.m_len = htonl(sizeof(YazRstResponse));
            pmsg.m_code = htonl(PCTRL_RST_ACK);
            pmsg.m_reason = 0;  // FIXME

            float mean = 0;
            int nsamp = 0;
            int nlost = 0;

            bool valid_measurement = getSpacing(&m_app_probes, mean, nsamp, nlost);
            yrr->m_app_mean = htonl((unsigned int)(mean));
            yrr->m_nsamples = htonl(nsamp);
            yrr->m_nlost = htonl(nlost);

            unsigned int ttl = 0;

#if HAVE_PCAP_H
            size_t napp_probes = m_app_probes.size();
#endif
            m_app_probes.clear();

#if HAVE_PCAP_H
            if (m_using_pcap)
            {
                int maxwait = pcap_wait_timeout;

                while (napp_probes > m_pcap_probes->size() && maxwait > 0)
                {
                    poll(0, 0, 10);
                    maxwait -= 10;
                }

                if (napp_probes > m_pcap_probes->size())
                {
                    std::cout << "##warning: didn't get all probes at pcap level" << std::endl;
                    std::cout << "##app probes<" << napp_probes << ">pcap probes<" << m_pcap_probes->size() << ">" << std::endl;
                }

                pthread_mutex_lock(m_pcap_mutex);
                valid_measurement = valid_measurement && 
                                    getSpacing(m_pcap_probes, mean, nsamp, nlost);

      
                valid_measurement = valid_measurement && 
                                    checkTTL(m_pcap_probes, ttl);
           
                m_pcap_probes->clear();
                pthread_mutex_unlock(m_pcap_mutex);
            }
#endif // HAVE_PCAP_H

            yrr->m_pcap_mean = htonl((unsigned int)(mean));
            yrr->m_ttl = htonl(ttl);
            yrr->m_nsamples = htonl(nsamp);
            yrr->m_nlost = htonl(nlost);

            if (!valid_measurement)
            {
                if (m_verbose)
                    std::cout << "##bad measurement - sending NACK probe sender" << std::endl;
                pmsg.m_code = htonl(PCTRL_RST_NACK);
                pmsg.m_len = 0;

                delete (yrr);
                yrr = 0;
                buffer = 0;
            }
        }
        break;

    default:
        if (m_verbose > 1)
            std::cout << "##received invalid control message " << std::endl;
        pmsg.m_code = htonl(PCTRL_INVALID);
        pmsg.m_len = 0;
        break;
    }


    // send pmsg, and if m_len > 0, buffer
    remain = sizeof(YazCtrlMsg);
    offset = 0;
    while (remain)
    {
        int n = send(sd, ((char *)&pmsg)+offset, remain, 0);
        if (n <= 0)
        {
            std::cerr << "!!error on send() of control message: " << errno << '/' << strerror(errno) << std::endl;
            throw -1;
        }

        remain -= n;
        offset += n;
    }

    remain = ntohl(pmsg.m_len);
    offset = 0;
    while (remain)
    {
        int n = send(sd, buffer+offset, remain, 0);
        if (n <= 0)
        {
            std::cerr << "!!error on send() of control payload: " << errno << '/' << strerror(errno) << std::endl;
            throw -1;
        }

        remain -= n;
        offset += n;
    }

    if (buffer)
        delete [] buffer;

    m_ctrl_seq++;
}


void YazReceiver::processProbe()
{
    char buffer[YAZBUFLEN];

    ssize_t rbytes = recv(m_probe_sd, buffer, YAZBUFLEN, 0);
    if (rbytes < 0)
    {
        std::cout << "!!recvfrom() (probe receive): " << errno << '/' << strerror(errno) << ")" << std::endl;
        return;
    }

    struct timeval tv;
    gettimeofday(&tv, 0);

    ProbeStamp ps;
    YazPkt *pp = (YazPkt*)buffer;
    ps.m_stream = ntohl(pp->m_stream);
    ps.m_sequence = ntohl(pp->m_sequence);
    ps.m_ts = tv;

    // subtract overhead from recvfrom() and gettimeofday()
    ps.m_ts.tv_usec -= m_syscall_overhead * 2;
    while (ps.m_ts.tv_usec < 0)
    {
        ps.m_ts.tv_sec -= 1;
        ps.m_ts.tv_usec += 1000000;
    }

    if (m_verbose > 1)
    {
        std::cout << ps.m_ts.tv_sec << '.' << std::setw(6) << std::setfill('0') << ps.m_ts.tv_usec << ' ' << ps.m_stream << ' ' << ps.m_sequence << std::endl;
    }

    m_app_probes.push_back(ps);
}


