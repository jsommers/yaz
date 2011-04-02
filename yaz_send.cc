/*
 * $Id: yaz_send.cc,v 1.87 2006/07/02 14:00:04 jsommers Exp $
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
#if HAVE_FLOAT_H
#include <float.h>
#endif
#include <math.h>

void YazSender::prepCtrl()
{
    m_ctrl_sd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_ctrl_sd < 0)
        throw -1;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, &m_target_addr, sizeof(struct in_addr));
    sin.sin_port = htons(DEST_CTRL_PORT);

    if (connect(m_ctrl_sd, (const struct sockaddr*)&sin, sizeof(struct sockaddr_in)) < 0)
    {
        std::cerr << "error connecting to receiver: " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    }
}


void YazSender::prepProbe()
{
    m_probe_sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_probe_sd < 0)
        throw -1;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = 0;
    if (bind(m_probe_sd, (const struct sockaddr*)&sin, sizeof(struct sockaddr_in)) < 0)
    {
        std::cerr << "error binding local probe socket: " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    }
   
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, &m_target_addr, sizeof(struct in_addr));
    sin.sin_port = htons(DEST_PORT);
    if (connect(m_probe_sd, (const struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0)
    {
        std::cerr << "error connecting probe socket to remote: " << errno << '/' << strerror(errno) << std::endl;
        throw -1;

    }
}


void YazSender::cleanup()
{
    close (m_probe_sd);
    close (m_ctrl_sd);
 
#if HAVE_PCAP_H
    unprepPcap();
#endif
}


bool YazSender::resetRemote()
{
    //
    // clean out any cruft from receiver.  mb just gets tossed --
    // we just want to make sure that the receiver is listening
    // and in a sane state.
    //
    MeasurementBundle mb;
    return (collectRemote(mb));
}


bool YazSender::collectRemote(MeasurementBundle &mb)
{
    // send RST message, get RST-ACK back along with mean spacings (and TTL).

    YazCtrlMsg pmsg;
    pmsg.m_code = htonl(PCTRL_RST);
    pmsg.m_len = 0;
    pmsg.m_seq = htonl(m_ctrl_seq);
    pmsg.m_reason = 0;

    int remain = sizeof(pmsg);
    int offset = 0;
    while (remain)
    {
        int n = send(m_ctrl_sd, ((char*)&pmsg)+offset, remain, 0);
        if (n <= 0)
        {
            std::cerr << "!!error on send() of RST message: " << errno << '/' << strerror(errno) << std::endl;
            return false;
        }

        remain -= n;
        offset += n;
    }


    struct timeval start, now, diff;
    gettimeofday(&start, 0);  
    int elapsed = 0;

    bool done = false;
    bool success = false;
    bool valid_measurement = false;
    while (!done)
    {
        pollfd pfd = {m_ctrl_sd, POLLIN, 0};
        int rv = poll(&pfd, 1, 1000);
        if (rv == -1)
        {
            std::cerr << "error in poll(): " << errno << '/' << strerror(errno) << std::endl;
            return false;
        }
        else if (rv == 1 && pfd.revents & POLLIN)
        {
            remain = sizeof(pmsg);
            offset = 0; 
            while (remain > 0)
            {
                int n = recv(m_ctrl_sd, ((char*)&pmsg)+offset, remain, 0);
                if (n <= 0)
                {
                    std::cerr << "!!error on recv() for control message: " << errno << '/' << strerror(errno) << std::endl;
                    return false;
                }

                remain -= n;
                offset += n;
            }

            if (ntohl(pmsg.m_code) == PCTRL_RST_NACK)
            {
                if (m_verbose)
                    std::cout << "!! bad measurement detected at receiver" << std::endl;
                valid_measurement = false;
                break;
            }

            assert (ntohl(pmsg.m_code) == PCTRL_RST_ACK);
            assert (ntohl(pmsg.m_seq) == (unsigned int)(m_ctrl_seq));
            assert (ntohl(pmsg.m_reason) == 0); // FIXME

            remain = ntohl(pmsg.m_len);
            YazRstResponse *yrr = new YazRstResponse();
            char *buffer = (char *)yrr;
            offset = 0; 
            while (remain > 0)
            {
                int n = recv(m_ctrl_sd, buffer+offset, remain, 0);
                if (n <= 0)
                {
                    std::cerr << "!!error on recv() for RST-ACK payload: " << errno << '/' << strerror(errno) << std::endl;
                    return false;
                }

                remain -= n;
                offset += n;
            }

            mb.m_remote_app_mean = float(ntohl(yrr->m_app_mean));
            mb.m_remote_pcap_mean = float(ntohl(yrr->m_pcap_mean));
            mb.m_remote_ttl = ntohl(yrr->m_ttl);
            mb.m_remote_nsamples = ntohl(yrr->m_nsamples);
            mb.m_remote_nlost = ntohl(yrr->m_nlost);

            float mean = 0;
            int nsamp = 0;
            int nlost = 0;
            
            valid_measurement = getSpacing(&m_app_probes, mean, nsamp, nlost, (m_target_spacing * 2));
            mb.m_local_app_mean = mean;
            mb.m_local_nsamples = nsamp;
            mb.m_local_nlost = nlost;

            unsigned int ttl = 0;

#if HAVE_PCAP_H
            size_t napp_probes = m_app_probes.size();
#endif
            m_app_probes.clear();

#if HAVE_PCAP_H
            if (m_using_pcap)
            {

                // assumption that at least as many probes will arrive at
                // app level as at pcap level.  seems reasonable, since 
                // most likely situation is that there are fewer at app level
                // than pcap.
                int maxwait = pcap_wait_timeout;

                while (napp_probes != m_pcap_probes->size() && maxwait > 0)
                {
                    poll (0, 0, 10);
                    maxwait -= 10;
                }

                if (napp_probes != m_pcap_probes->size())
                    std::cout << "##warning: didn't get all probes at pcap level" << std::endl;

                pthread_mutex_lock(m_pcap_mutex);
                valid_measurement = 
                    getSpacing(m_pcap_probes, mean, nsamp, nlost, (m_target_spacing * 2));

                valid_measurement = valid_measurement && 
                    checkTTL(m_pcap_probes, ttl);
                m_pcap_probes->clear();
                pthread_mutex_unlock(m_pcap_mutex);
            }
#endif // HAVE_PCAP_H

            mb.m_local_pcap_mean = mean;
            mb.m_local_ttl = ttl;
            mb.m_local_nsamples = nsamp;
            mb.m_local_nlost = nlost;

            m_ctrl_seq++;
            done = true;
            success = true;
        }
        else if (rv == 0)
        {
            gettimeofday(&now, 0);
            timersub(&now, &start, &diff);
            elapsed = int(diff.tv_sec * 1000.0 + diff.tv_usec / 1000.0);
            if (elapsed > ctrl_msg_timeout)
            {
                std::cerr << "!!no RST response from remote after waiting " << ctrl_msg_timeout << " milliseconds." << std::endl;
                done = true;
                success = false;
            }
        }
    }

    return (success && valid_measurement);
}


bool YazSender::doOneMeasurementRound(std::list<MeasurementBundle> *mb_list)
{
    MeasurementBundle mb;

    int maxattempt = m_nstreams;

    int streamnum = 1;
    while (streamnum <= m_nstreams && maxattempt)
    {
        mb.reset();

        gettimeofday(&mb.m_start, 0);
        m_curr_stream++;
        sendStream();
        gettimeofday(&mb.m_end, 0);

        usleep(2000);

        if (!collectRemote(mb))
        {
            maxattempt--;
            continue;
        }

        if (int(mb.m_remote_nlost) > 1)
        {
            std::cout << "## pkts lost --- backing off: " << mb.m_remote_nlost << std::endl;
        }
        else if (int(mb.m_remote_nsamples) < m_stream_length/2)
        {
            maxattempt--;
            std::cout << "## not enough samples from receiver: " << mb.m_remote_nsamples;
            continue;
        }

        if (m_verbose > 1)
            std::cout << "nsamples: " << mb.m_remote_nsamples << std::endl;

        MeasurementBundle bx = mb;
        mb_list->push_back(bx);
        streamnum++;

        maxattempt = m_nstreams;
    }

    return (maxattempt != 0);
}


void YazSender::coalesceMeasurements(std::list<MeasurementBundle> *mblist,
                                     MeasurementBundle &mbresult)
{
    // collect mean from list, push onto master list
    typedef std::list<MeasurementBundle>::iterator MBI;
    MBI iter = mblist->begin();
    mbresult = *iter;
    int n = 1;
    while (++iter != mblist->end())
    {
        mbresult.m_local_app_mean += iter->m_local_app_mean;
        mbresult.m_local_pcap_mean += iter->m_local_pcap_mean;

        mbresult.m_remote_app_mean += iter->m_remote_app_mean;
        mbresult.m_remote_pcap_mean += iter->m_remote_pcap_mean;
        mbresult.m_end = iter->m_end;

        mbresult.m_local_nsamples += iter->m_local_nsamples;
        mbresult.m_local_nlost += iter->m_local_nlost;

        mbresult.m_remote_nsamples += iter->m_remote_nsamples;
        mbresult.m_remote_nlost += iter->m_remote_nlost;

        n++;
    }

    mbresult.m_local_app_mean /= n;
    mbresult.m_local_pcap_mean /= n;
    mbresult.m_remote_app_mean /= n;
    mbresult.m_remote_pcap_mean /= n;
}


bool YazSender::isPathSame(std::list<MeasurementBundle> *mblist)
{
    bool rv = true;
    typedef std::list<MeasurementBundle>::iterator MBI;
    MBI iterI = mblist->begin();
    MBI iterJ = iterI;
    iterI++;
    while (iterI != mblist->end())
    {
        // make sure TTLs don't change at each end point
        if (iterI->m_local_ttl - iterI->m_remote_ttl !=
            iterJ->m_local_ttl - iterJ->m_remote_ttl)
        {
            std::cout << "!! error: path length changed during measurement." << std::endl;
            rv = false;
            break;
        }
        iterI++;
        iterJ++;
    }
    return rv;
}



bool YazSender::localSpacingConsistent(std::list<MeasurementBundle> *mblist)
{
    bool rv = true;

#if 0 // FIXME
    for (std::list<MeasurementBundle>::iterator iterI = mblist->begin();
         iterI != mblist->end(); ++iterI)
    {
        if (fabs(iterI->m_local_pcap_mean - m_target_spacing) >
            std::max(2.0f, (m_threshold * m_target_spacing)))
        {
            std::cout << "!! error: inconsistent local spacing." << std::endl;
            rv = false;
            break;
        }
    }
#endif

    return (rv);
}


void YazSender::run()
{
    char buffer[YAZTINYBUF];
    memset(&buffer, 0, YAZTINYBUF);
    inet_ntop(AF_INET, &m_target_addr, buffer, YAZTINYBUF-1);

#if HAVE_PCAP_H
    std::ostringstream ostr;
    ostr << "udp and host " << buffer;
    m_pcap_filter_string = ostr.str(); 
#endif

    std::list<MeasurementBundle> *measurement_list = new std::list<MeasurementBundle>();

    try
    {
        // setup control, probe, pcap
        prepCtrl();
        prepProbe();
#if HAVE_PCAP_H
        prepPcap();
#endif

        // send RST as a ping and to clean out any measurements from remote side
        if (!resetRemote())
        {
            std::cerr << "!! error doing initial jig with remote.  bailing out. (restart receiver and try again.)" << std::endl;
            throw -1;
        }

        int saved_pkt_size = m_curr_pkt_size;
        int fastest_local = MAX_SPACE;
        int max_space = std::max( int(float(m_min_pkt_size * 8) / m_resolution), MAX_SPACE);
        std::cout << "## setting max_space to be " << max_space << std::endl;

        float current_estimate = 0.0;
        int runnum = 1;

        do // until doomsday
        {
            struct timeval tvbegin;
            gettimeofday(&tvbegin, 0);
     
            m_target_spacing = MIN_SPACE;
            m_curr_pkt_size = saved_pkt_size;

            if (m_verbose) 
                std::cout << "## starting sample " << runnum << std::endl;

            if (m_verbose > 1) 
                std::cout << "## sample " << runnum << ", initial spacing:" << m_target_spacing << std::endl;


            measurement_list->clear();

            bool done = false;
            int local_crawl = RETRY_LIMIT;
#if 0
            int local_forgiveness = RETRY_LIMIT;
            while (!done && local_crawl && local_forgiveness)
#endif
            while (!done && local_crawl)
            {
                if (!doOneMeasurementRound(measurement_list))
                {
                    std::cerr << "!! persistent error collecting measurements from receiver" << std::endl;
                    throw -1;
                }

                if (!isPathSame(measurement_list))
                {
                    std::cerr << "!! path length changed --- bailing out." << std::endl;
                    throw -1;
                }

                MeasurementBundle mb;
                coalesceMeasurements(measurement_list, mb);

#if 0
                if (fabs(mb.m_local_pcap_mean - float(m_target_spacing)) > 2.0)
                {
                    std::cout << "## asked for " << m_target_spacing << " but got " << mb.m_local_pcap_mean << " -- retrying"  << std::endl;
                    local_forgiveness--;
                    continue;
                }
#endif

                measurement_list->clear();


                //
                // given our current probe rate (mb.m_local_pcap_mean), what is range of compression
                // or expansion that allows the rate to be within our target resolution (with
                // a minimum of 2 microseconds, which only matters at rather fast probe rates.)
                //
                float curr_rate = ((m_curr_pkt_size * 8.0) / mb.m_local_pcap_mean) * 1000000;
                float resol_spc = (m_curr_pkt_size * 8.0) / (curr_rate - m_resolution) * 1000000 - mb.m_local_pcap_mean;
                float maxdiff = std::max(1.0f, resol_spc);
                bool compexp =  
                    (fabs(mb.m_remote_pcap_mean - mb.m_local_pcap_mean) > maxdiff);

                // force lower rate if there's packet loss
                compexp = compexp || (mb.m_remote_nlost > 1);

                if (!compexp && (m_curr_pkt_size == saved_pkt_size))
                    fastest_local = std::min(fastest_local, int(mb.m_local_pcap_mean));

                if (m_verbose)
                {
                    std::cout << "## local spacing: " 
                              << mb.m_local_pcap_mean << std::endl;
                    std::cout << "## remote spacing: " 
                              << mb.m_remote_pcap_mean << std::endl;
                    std::cout << "## compexp: " << compexp << std::endl;

                    if (mb.m_remote_ttl && mb.m_local_ttl)
                        std::cout << "path length: " << (mb.m_local_ttl - mb.m_remote_ttl) << " hops" << std::endl;
                }


                if (compexp)
                {
                    // even though our local spacing was consistent,
                    // it may not be the same as our target spacing.
                    // thus, there may indeed be stream compression or
                    // expansion.
                    if (m_target_spacing == mb.m_remote_pcap_mean)
                    {
                        m_target_spacing += 2;
                        local_crawl--;
                    }
                    else
                    {
                        float diff = fabs(mb.m_remote_pcap_mean - mb.m_local_pcap_mean);
                        m_target_spacing = int(mb.m_local_pcap_mean + diff / 2);
                    }

                    if (m_verbose)
                        std::cout << "new target: " << m_target_spacing << std::endl;

                    if (m_target_spacing >= max_space)
                    {
                        if (m_curr_pkt_size == m_min_pkt_size)
                        {
                            std::cout << "## avbw too low to accurately measure." << std::endl;
                            done = true;
                            current_estimate = 0.0;
                        }

                        while (m_target_spacing > max_space)
                        {
                            m_curr_pkt_size /= 2;
                            m_curr_pkt_size = std::max(m_curr_pkt_size, m_min_pkt_size);
                            std::cout << "## rate too high with current packet size.  cut packet size to: " << m_curr_pkt_size << std::endl;
                            m_target_spacing /= 2;
                        }
                    }
                }
                else
                {   
                    current_estimate = (float(m_curr_pkt_size) * 8.0 ) / (mb.m_local_pcap_mean / 1000000.0);
                    done = true;
                    if (m_verbose)
                        std::cout << "## done. setting current estimate to " << current_estimate/1000.0 << std::endl;

#if 0 // needs fixing
                    if (abs(m_target_spacing - fastest_local) <= 2)
                        std::cout << "## available bandwidth too high to accurately measure." << std::endl;
#endif
                }

                // set sleep time to be exponentially distributed 
                int sleeptime = int(-1 * (m_inter_stream_spacing/1000) * log(1.0 - (random() / double(INT_MAX))));
                usleep(sleeptime * 1000);
            }
        
            struct timeval tvend;
            gettimeofday(&tvend, 0);
        
            std::cout << runnum << " "
                      << tvbegin.tv_sec << '.' 
                      << std::setw(6) << std::setfill('0') 
                      << tvbegin.tv_usec << " "
                      << tvend.tv_sec << '.' 
                      << std::setw(6) << std::setfill('0') 
                      << tvend.tv_usec << " "
                      << std::setprecision(0)
                      << std::fixed
                      << current_estimate/1000.0 << std::endl;

            runnum++;

            current_estimate = 0.0;

            // set sleep time to be exponentially distributed 
            int sleeptime = int(-1 * (m_inter_stream_spacing/100) * log(1.0 - (random() / double(INT_MAX))));
            usleep(sleeptime * 1000);
        }  while (1);
    }
    catch (...)
    {
        std::cerr << "!! yaz sender exiting" << std::endl;
        cleanup();
    }

    delete (measurement_list);

#if HAVE_PCAP_H
    *m_running = false;
    if (m_using_pcap && *m_pcap_thread)
        pthread_cancel(*m_pcap_thread);
#endif

    return;
}


void YazSender::sendProbe(char *buffer, int paylen, int stream, int seq)
{
    YazPkt *pp = (YazPkt*)buffer;
    pp->m_stream = htonl(stream);
    pp->m_sequence = htonl(seq);
    if (send(m_probe_sd, (char *)pp, paylen, 0) != paylen)
    {
        std::cerr << "!! error sending probe: " << errno << '/' << strerror(errno) << std::endl;
        throw -1;
    }
}


void YazSender::sendStream()
{
    // m_target_spacing is intended pkt spacing, in microseconds
    // probes should be m_curr_pkt_size
    // send m_stream_length packets

    struct timeval now, target, diff;
    int payload_size = m_curr_pkt_size - sizeof(struct ip) - sizeof(struct udphdr);
    char *buffer = new char[payload_size];
    memset(buffer, 0, payload_size);

    int seq = 0;
    ProbeStamp ps;
    ps.m_stream = m_curr_stream;
    ps.m_ttl = 0;
    ps.m_sequence = seq;

    struct timeval target_tv = { 0, m_target_spacing };

    gettimeofday(&now, 0);
    timeradd(&now, &target_tv, &target);
    sendProbe(buffer, payload_size, m_curr_stream, seq++);
    ps.m_ts = now;
    m_app_probes.push_back(ps);

    int remaining = m_stream_length;
    while (--remaining > 0)
    {
        gettimeofday(&now, 0);
        timersub(&target, &now, &diff);
        int usec_remain = (diff.tv_sec * 1000000 + diff.tv_usec);

        //
        // FIXME ??? mult by 2 ??? we already take mean and at 3 * stdev...
        //
        // int sleepy = usec_remain - m_min_sleep * 2;
        int sleepy = usec_remain - m_min_sleep;
        if (sleepy > 0)
            usleep(sleepy);

        while (1)
        {
            gettimeofday(&now, 0);
            timersub(&target, &now, &diff);
            usec_remain = (diff.tv_sec * 1000000 + diff.tv_usec);

            //
            // what's justification for div 2?  does this cause the
            // half micro shift above the target spacing?
            //
            if (usec_remain < (m_syscall_overhead/2))
                break;
        }

        sendProbe(buffer, payload_size, m_curr_stream, seq);

        timeradd(&now, &target_tv, &target);
        ps.m_sequence = seq++;
        ps.m_ts = now;
        m_app_probes.push_back(ps);
        if (timercmp(&now, &target, >))
        {
            std::cout << "!! probe stream too fast to generate.  aborting" << std::endl;
            break;
        }
    }
    delete [] buffer;
}

