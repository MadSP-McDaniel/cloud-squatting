include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -std=c++17  -o mergecap2 main.o $(PCAPPP_LIBS) -lstdc++fs

# Clean Target
clean:
	rm main.o
	rm mergecap2