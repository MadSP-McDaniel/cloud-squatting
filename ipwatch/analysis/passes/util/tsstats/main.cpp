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

	unordered_map<time_t, uint64_t> ts_sessions;


	// use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
	// and create an interface instance that both readers implement
	pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("/dev/stdin");

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
		ts_sessions[ts.tv_sec]++;
	}

	// close reader
	reader->close();

	// free reader memory because it was created by pcpp::IFileReaderDevice::getReader()
	delete reader;

	for (auto it = ts_sessions.begin(); it != ts_sessions.end(); it++)
	{
		printf("%lu\t%lu\n",
				it->first, it->second
		);
	}
}
