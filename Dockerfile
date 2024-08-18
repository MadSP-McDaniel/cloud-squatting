FROM ubuntu:20.04

# https://upcloud.com/community/tutorials/install-snort-ubuntu/

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y gcc libpcre3-dev zlib1g-dev libluajit-5.1-dev \
    libpcap-dev openssl libssl-dev libnghttp2-dev libdumbnet-dev \
    bison flex libdnet autoconf libtool wget build-essential sudo python3.9 python3-pip tshark tcpdump tcpreplay curl

WORKDIR /tmp/snort_src

RUN wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz && \
    tar -xvzf daq-2.0.7.tar.gz && cd daq-2.0.7 && \
    autoreconf -f -i && ./configure && make && make install

RUN wget https://www.snort.org/downloads/snort/snort-2.9.17.tar.gz && \
    tar -xvzf snort-2.9.17.tar.gz && cd snort-2.9.17 && \
    ./configure --enable-sourcefire && make && make install && ldconfig

WORKDIR /tmp/zeek_src

# https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek
RUN sudo echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security:zeek.gpg > /dev/null
RUN sudo apt update && \
    sudo DEBIAN_FRONTEND=noninteractive apt install -yq zeek

ENV PATH=/opt/zeek/bin:$PATH

RUN wget https://github.com/seladb/PcapPlusPlus/archive/v20.08.tar.gz && tar xzf v20.08.tar.gz
RUN cd Pcap* && ./configure-linux.sh --default && make -j24 && make install

COPY ./requirements.txt /ipreuse/requirements.txt
RUN pip3 install -r /ipreuse/requirements.txt

COPY ./ipwatch/analysis/passes/util/ /tmp/util_make
RUN cd /tmp/util_make/ipportextract && make
RUN cd /tmp/util_make/ipportstats && make
RUN cd /tmp/util_make/mergecap && make
RUN cd /tmp/util_make/mergecap2 && make
RUN cd /tmp/util_make/tsstats && make


COPY . /ipreuse
RUN cp -r /tmp/util_make/* /ipreuse/ipwatch/analysis/passes/util

WORKDIR /ipreuse
