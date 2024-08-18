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

	pcpp::IFileWriterDevice *writer = new pcpp::PcapNgFileWriterDevice("/dev/stdout");

	if (!writer->open())
	{
		fprintf(stderr, "Failed to open writer");
		exit(1);
	}

	for (int i = 1; i < argc; i++)
	{
		pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(argv[i]);

		// verify that a reader interface was indeed created
		if (reader == nullptr)
		{
			fprintf(stderr, "Failed to open reader %s", argv[i]);
			exit(1);
		}

		// open the reader for reading
		if (!reader->open())
		{
			fprintf(stderr, "Failed to open reader %s", argv[i]);
			exit(1);
		}

		pcpp::RawPacket rawPacket;

		while (reader->getNextPacket(rawPacket))
		{
			writer->writePacket(rawPacket);
		}

		reader->close();

		// free reader memory because it was created by pcpp::IFileReaderDevice::getReader()
		delete reader;
	}

	writer->close();
	delete writer;
}
