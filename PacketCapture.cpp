// PacketCapture.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <iostream>
#include <memory>
#include <csignal>
#include <atomic>
#include <IPv4Layer.h>
#include "PcapLiveDeviceList.h"
#include <PcapFileDevice.h>
#include "stdlib.h"
#include "SystemUtils.h"
#include <string>
#include <sstream>
#include <IpAddress.h>
#include <Packet.h>
#include <PcapFilter.h>

std::atomic_bool stopCapture{ false };

void onSigInt(int)

{
    std::cout << "Stopping packet capture \n";
    stopCapture = true;
}

void layerParser(const pcpp::Packet& first) // Prints data from the protocol layers from lowest to highest
{
    for (pcpp::Layer* parser{ first.getFirstLayer() }; parser != nullptr; parser = parser->getNextLayer())
        std::cout << parser->toString() << '\n';

    std::cout << '\n';
}

std::string getLocalIp() 
{
    auto deviceList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    for (auto device : deviceList)
    {
        if (device->getDefaultGateway() != pcpp::IPv4Address::Zero)
        {
            return device->getIPv4Address().toString();
        }
    }
    return "";
}

int main(int argc, char* argv[])
{

    std::signal(SIGINT, onSigInt);

    const std::string interfaceIP = getLocalIp();

    // queries the OS for interfaces and creates an object for each one it finds (only one here) + other info (MAC addresses)

    auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);

    
    if (dev == nullptr) 
    {
        std::cerr << "No device found\n";
        return 1;
    }
        
        std::cout << "Interface found\n";

        std::cout << dev->getName() << std::endl;
        std::cout << dev->getDesc() << std::endl;
        std::cout << dev->getMacAddress() << std::endl;
        std::cout << dev->getDefaultGateway() << std::endl;
        std::cout << dev->getMtu() << std::endl;

    std::cout << "Starting asynchronous packet capture with packet vector... \n";

    if (!dev->open()) 
    {
        std::cerr << "Cannot open device";
        return 1;
    }

    if (argc > 1)
    {
        std::stringstream convert{ argv[1] };
        uint16_t port_number{};

        if (!(convert >> port_number))
        {
            std::cerr << "Invalid port number\n";
            return 1;
        }
            
        pcpp::PortFilter port{ port_number, pcpp::SRC_OR_DST };
        
        if (!(dev->setFilter(port)))
        {
            std::cerr << "Failed to set port filter\n";
            return 1;
        }

    }
    struct PacketStats
    {
        int ethPacketCount{ 0 };
        int ipv4PacketCount{ 0 };
        int tcpPacketCount{ 0 };
        int udpPacketCount{ 0 };
        int ipv6PacketCount{ 0 };
        int sslPacketCount{ 0 };
        int httpPacketCount{ 0 };
        int dnsPacketCount{ 0 };
        int arpPacketCount{ 0 };

        void clearPacketStats() { ethPacketCount = ipv4PacketCount = tcpPacketCount = udpPacketCount = ipv6PacketCount = sslPacketCount = httpPacketCount = dnsPacketCount = arpPacketCount = 0; }

        void consumePacket(pcpp::Packet& packet)
        {
            if (packet.isPacketOfType(pcpp::Ethernet))
                ethPacketCount++;
            if (packet.isPacketOfType(pcpp::IPv4))
                ipv4PacketCount++;
            if (packet.isPacketOfType(pcpp::IPv6))
                ipv6PacketCount++;
            if (packet.isPacketOfType(pcpp::TCP))
                tcpPacketCount++;
            if (packet.isPacketOfType(pcpp::UDP))
                udpPacketCount++;
            if (packet.isPacketOfType(pcpp::DNS))
                dnsPacketCount++;
            if (packet.isPacketOfType(pcpp::HTTP))
                httpPacketCount++;
            if (packet.isPacketOfType(pcpp::SSL))
                sslPacketCount++;
            if (packet.isPacketOfType(pcpp::ARP))
                arpPacketCount++;
        }

        void printToConsole()
        {
            std::cout
                << "Ethernet packet count: " << ethPacketCount << std::endl
                << "IPv4 packet count:     " << ipv4PacketCount << std::endl
                << "IPv6 packet count:     " << ipv6PacketCount << std::endl
                << "TCP packet count:      " << tcpPacketCount << std::endl
                << "UDP packet count:      " << udpPacketCount << std::endl
                << "DNS packet count:      " << dnsPacketCount << std::endl
                << "HTTP packet count:     " << httpPacketCount << std::endl
                << "SSL packet count:      " << sslPacketCount << std::endl
                << "ARP packet count:      " << arpPacketCount << std::endl;
        }

    };

    PacketStats stats;

    //Empty packet vector object
    pcpp::RawPacketVector packetVector;
    
    //Start capture
    dev->startCapture(packetVector);

    while (!stopCapture)
    {
        pcpp::multiPlatformSleep(1);
    }

    dev->stopCapture();
  
    for (const auto& packet : packetVector)
    {
        pcpp::Packet parsedPacket(packet);
        stats.consumePacket(parsedPacket);
        layerParser(parsedPacket);
    }
    stats.printToConsole();

    pcpp::PcapFileWriterDevice writer("mypcap.pcap", pcpp::LINKTYPE_ETHERNET);

    if (!writer.open())
    {
        std::cerr << "Error: Cannot open pcap file for writing\n";
    }

    for (pcpp::RawPacket* rawPacket : packetVector)
    {
        writer.writePacket(*rawPacket);
    }

    writer.close();

    std::cout << "Successfully wrote " << packetVector.size() << " packets to mypcap.pcap\n";

        /*
        * Next improvements: Expand on filtering -> src and dst port setting, more advanced filtering; Better command line argument input method;
        * Live packet summaries; Establish IDS methods;
        */

    return 0;
}