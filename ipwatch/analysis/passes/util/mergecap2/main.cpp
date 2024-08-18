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
#include <experimental/filesystem>
#include <iostream>

/**
 * main method of the application
 */
int main(int argc, char *argv[])
{

	pcpp::IFileWriterDevice *writer = new pcpp::PcapNgFileWriterDevice("/dev/stdout");

	if (!writer->open())
	{
		fprintf(stderr, "Failed to open writer");
		exit(1);
	}

	pcpp::IPv4Address privateRange("172.16.0.0"), privateMask("255.240.0.0");


	int count = 0;

    while(std::cin) {
		std::string file, ip;
		std::getline(std::cin, file);
		std::getline(std::cin, ip);
		if(file == "") {
			break;
		}
		count++;
		if (count % 10000 == 0) {
			std::cerr << count << std::endl;
		}
		pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(file.c_str());
		pcpp::IPv4Address address(ip);

		// verify that a reader interface was indeed created
		if (reader == nullptr)
		{
			fprintf(stderr, "Failed to open reader %s", file.c_str());
			exit(1);
		}

		// open the reader for reading
		if (!reader->open())
		{
			fprintf(stderr, "Failed to open reader %s", file.c_str());
			exit(1);
		}

		pcpp::RawPacket rawPacket;

		while (reader->getNextPacket(rawPacket))
		{

			pcpp::Packet parsedPacket(&rawPacket);

			pcpp::IPv4Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			if (ipLayer == NULL)
			{
				printf("Something went wrong, couldn't find IPv4 layer\n");
				exit(1);
			}

			if(ipLayer->getSrcIpAddress().matchSubnet(privateRange, privateMask)) {
				ipLayer->setSrcIpAddress(address);
			}

			if(ipLayer->getDstIpAddress().matchSubnet(privateRange, privateMask)) {
				ipLayer->setDstIpAddress(address);
			}

			parsedPacket.computeCalculateFields();

			writer->writePacket(*(parsedPacket.getRawPacket()));
		}

		reader->close();

		// free reader memory because it was created by pcpp::IFileReaderDevice::getReader()
		delete reader;
	}

	writer->close();
	delete writer;
}
