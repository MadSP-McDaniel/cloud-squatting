#if !defined(WIN32) && !defined(WINx64)
#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include <unordered_map>
#include <unordered_set>
#include <cstdio>
#include <sys/stat.h>
#include <fcntl.h>
using namespace std;

/**
 * main method of the application
 */
int main(int argc, char *argv[])
{

	unordered_map<uint32_t, unordered_set <uint16_t>> ports;
	unordered_map<uint32_t, unordered_set <uint32_t>> ips;
	unordered_map<uint32_t, unordered_set <uint64_t>> pairs;
	unordered_map<uint32_t, uint64_t> sessions;
	
	// Port stats
	unordered_map<uint16_t, uint64_t> port_session_counts;
	unordered_map<uint16_t, unordered_set <uint32_t>> port_ip_clients;

	auto fd = fopen(argv[2], "w");


	// use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
	// and create an interface instance that both readers implement
	pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(argv[1]);

	// verify that a reader interface was indeed created
	if (reader == NULL)
	{
		exit(1);
	}

	// open the reader for reading
	if (!reader->open())
	{
		exit(1);
	}

	// set a BPF filter for the reader - only packets that match the filter will be read
	if (!reader->setFilter("tcp[0xd]&18=2"))
	{
		exit(1);
	}

	// the packet container
	pcpp::RawPacket rawPacket;

	// a while loop that will continue as long as there are packets in the input file
	// matching the BPF filter
	while (reader->getNextPacket(rawPacket))
	{
		pcpp::Packet parsedPacket(&rawPacket);

		pcpp::IPv4Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
		if (ipLayer == NULL)
		{
			printf("Something went wrong, couldn't find IPv4 layer\n");
			exit(1);
		}

		pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
		if (tcpLayer == NULL)
		{
			printf("Something went wrong, couldn't find TCP layer\n");
			exit(1);
		}
		timespec ts = rawPacket.getPacketTimeStamp();
		fprintf(fd, "%s\t%d\t%s\t%d\t%lld.%.9ld\n",
			   ipLayer->getSrcIpAddress().toString().c_str(),
			   (int)ntohs(tcpLayer->getTcpHeader()->portSrc),
			   ipLayer->getDstIpAddress().toString().c_str(),
			   (int)ntohs(tcpLayer->getTcpHeader()->portDst),
			   (long long)ts.tv_sec, ts.tv_nsec);

		auto dstport = (uint16_t)ntohs(tcpLayer->getTcpHeader()->portDst);
		ports[ipLayer->getSrcIpAddress().toInt()].insert(dstport);
		ips[ipLayer->getSrcIpAddress().toInt()].insert(ipLayer->getDstIpAddress().toInt());
		pairs[ipLayer->getSrcIpAddress().toInt()].insert((uint64_t)dstport ^ (((uint64_t)ipLayer->getDstIpAddress().toInt())<<32));
		sessions[ipLayer->getSrcIpAddress().toInt()]++;
		port_session_counts[dstport]++;
		port_ip_clients[dstport].insert(ipLayer->getDstIpAddress().toInt());
	}

	fclose(fd);

	// close reader
	reader->close();

	// free reader memory because it was created by pcpp::IFileReaderDevice::getReader()
	delete reader;

	fd = fopen(argv[3], "w");


	for (auto it = pairs.begin(); it != pairs.end(); it++)
	{

		pcpp::IPv4Address addr(it->first);

		fprintf(fd, "%s\t%lu\t%lu\t%lu\t%lu\n",
				addr.toString().c_str(),
				ips[it->first].size(),
				ports[it->first].size(),
				pairs[it->first].size(),
				sessions[it->first]
		);
	}

	fclose(fd);

	fd = fopen(argv[4], "w");


	for (auto it = port_session_counts.begin(); it != port_session_counts.end(); it++)
	{

		fprintf(fd, "%u\t%lu\t%lu\n",
				it->first,
				it->second,
				port_ip_clients[it->first].size()
		);
	}

	fclose(fd);

}
