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

/**
 * main method of the application
 */
int main(int argc, char *argv[])
{
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

		printf("%s\t%d\t%s\t%d\t%lld.%.9ld\n",
			   ipLayer->getSrcIpAddress().toString().c_str(),
			   (int)ntohs(tcpLayer->getTcpHeader()->portSrc),
			   ipLayer->getDstIpAddress().toString().c_str(),
			   (int)ntohs(tcpLayer->getTcpHeader()->portDst),
			   (long long)ts.tv_sec, ts.tv_nsec);
	}

	// close reader
	reader->close();

	// free reader memory because it was created by pcpp::IFileReaderDevice::getReader()
	delete reader;
}
