//
// Copyright (C) 2012 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include <algorithm>

#include "INETDefs.h"
#include "IPvXAddress.h"
#include "IPvXAddressResolver.h"

#ifdef WITH_IPv4
#include "IPv4Datagram.h"
#endif

#ifdef WITH_IPv6
#include "IPv6Datagram.h"
#endif

#ifdef WITH_UDP
#include "UDPPacket.h"
#endif

#ifdef WITH_TCP_COMMON
#include "TCPSegment.h"
#endif

#include "IDSCPClassifier.h"
#include "DiffservUtil.h"

using namespace DiffservUtil;

/**
 * Multi-Field classifier (RFC 2475 2.3.1, RFC 3290 4.2.2).
 *
 * This classifier contains a list of filters that identifies
 * the flows and assign the DSCP to them.
 * Each filter can match the source and destination address,
 * IP protocol number, source and destination ports, or ToS
 * of the datagram. The first matching filter determines
 * the Diffserv code point of the packet.
 */
class INET_API MFClassifier : public IDSCPClassifier
{
  protected:
    struct Filter
    {
        int dscp;

        IPvXAddress srcAddr;
        int srcPrefixLength;
        IPvXAddress destAddr;
        int destPrefixLength;
        int protocol;
        int tos;
        int tosMask;
        int srcPortMin;
        int srcPortMax;
        int destPortMin;
        int destPortMax;

        Filter() : dscp(DSCP_BE),
                   srcPrefixLength(0), destPrefixLength(0), protocol(-1), tos(0), tosMask(0),
                   srcPortMin(-1), srcPortMax(-1), destPortMin(-1), destPortMax(-1)  {}
#ifdef WITH_IPv4
        bool matches(IPv4Datagram *datagram);
#endif
#ifdef WITH_IPv6
        bool matches(IPv6Datagram *datagram);
#endif
    };

    std::vector<Filter> filters;

    void addFilter(const Filter &filter);
    static bool lessFilter(const Filter &filter1, const Filter &filter2);

  public:
    virtual void configure(cXMLElement *config, cSimpleModule &owner);

    /**
     * Classify packet according to source/destination address/port and protocol number.
     * Note: fragments cannot be properly classified.
     */
    virtual int classifyPacket(cPacket *msg);
};

Register_Class(MFClassifier);

#ifdef WITH_IPv4
bool MFClassifier::Filter::matches(IPv4Datagram *datagram)
{
    if (srcPrefixLength > 0 && (srcAddr.isIPv6() || !datagram->getSrcAddress().prefixMatches(srcAddr.get4(), srcPrefixLength)))
        return false;
    if (destPrefixLength > 0 && (destAddr.isIPv6() || !datagram->getDestAddress().prefixMatches(destAddr.get4(), destPrefixLength)))
        return false;
    if (protocol >= 0 && datagram->getTransportProtocol() != protocol)
        return false;
    if (tosMask != 0 && (tos & tosMask) != (datagram->getTypeOfService() & tosMask))
        return false;
    if (srcPortMin >= 0 || destPortMin >= 0)
    {
        int srcPort = -1, destPort = -1;
        if (datagram->getTransportProtocol() == IP_PROT_UDP)
        {
#ifdef WITH_UDP
            UDPPacket *udpPacket = check_and_cast<UDPPacket*>(datagram->getEncapsulatedPacket());
            srcPort = udpPacket->getSourcePort();
            destPort = udpPacket->getDestinationPort();
#endif
        }
        else if (datagram->getTransportProtocol() == IP_PROT_TCP)
        {
#ifdef WITH_TCP_COMMON
            TCPSegment *tcpSegment = check_and_cast<TCPSegment*>(datagram->getEncapsulatedPacket());
            srcPort = tcpSegment->getSrcPort();
            destPort = tcpSegment->getDestPort();
#endif
        }

        if (srcPortMin >= 0 && (srcPort < srcPortMin || srcPort > srcPortMax))
            return false;
        if (destPortMin >= 0 && (destPort < destPortMin || destPort > destPortMax))
            return false;
    }

    return true;
}
#endif

#ifdef WITH_IPv6
bool MFClassifier::Filter::matches(IPv6Datagram *datagram)
{
    if (srcPrefixLength > 0 && (!srcAddr.isIPv6() || !datagram->getSrcAddress().matches(srcAddr.get6(), srcPrefixLength)))
        return false;
    if (destPrefixLength > 0 && (!destAddr.isIPv6() || !datagram->getDestAddress().matches(destAddr.get6(), destPrefixLength)))
        return false;
    if (protocol >= 0 && datagram->getTransportProtocol() != protocol)
        return false;
    if (tosMask != 0 && (tos & tosMask) != (datagram->getTrafficClass() & tosMask))
        return false;
    if (srcPortMin >= 0 || destPortMin >= 0)
    {
        int srcPort = -1, destPort = -1;
        if (datagram->getTransportProtocol() == IP_PROT_UDP)
        {
#ifdef WITH_UDP
            UDPPacket *udpPacket = check_and_cast<UDPPacket*>(datagram->getEncapsulatedPacket());
            srcPort = udpPacket->getSourcePort();
            destPort = udpPacket->getDestinationPort();
#endif
        }
        else if (datagram->getTransportProtocol() == IP_PROT_TCP)
        {
#ifdef WITH_TCP_COMMON
            TCPSegment *tcpSegment = check_and_cast<TCPSegment*>(datagram->getEncapsulatedPacket());
            srcPort = tcpSegment->getSrcPort();
            destPort = tcpSegment->getDestPort();
#endif
        }

        if (srcPortMin >= 0 && (srcPort < srcPortMin || srcPort > srcPortMax))
            return false;
        if (destPortMin >= 0 && (destPort < destPortMin || destPort > destPortMax))
            return false;
    }

    return true;
}
#endif

int MFClassifier::classifyPacket(cPacket *msg)
{
#ifdef WITH_IPv4
    if (dynamic_cast<IPv4Datagram *>(msg))
    {
        IPv4Datagram *datagram = (IPv4Datagram *)msg;
        for (std::vector<Filter>::iterator it = filters.begin(); it != filters.end(); ++it)
            if (it->matches(datagram))
                return it->dscp;
    }
    else
#endif
#ifdef WITH_IPv6
    if (dynamic_cast<IPv6Datagram *>(msg))
    {
        IPv6Datagram *datagram = (IPv6Datagram *)msg;
        for (std::vector<Filter>::iterator it = filters.begin(); it != filters.end(); ++it)
            if (it->matches(datagram))
                return it->dscp;
    }
    else
#endif
    {
    }

    return DSCP_BE;
}

void MFClassifier::addFilter(const Filter &filter)
{
    if (filter.dscp < 0 || filter.dscp >= DSCP_MAX)
        throw cRuntimeError("dscp is out of range [0,%d).", DSCP_MAX);
    if (!filter.srcAddr.isUnspecified() && ((filter.srcAddr.isIPv6() && filter.srcPrefixLength > 128) ||
                                            (!filter.srcAddr.isIPv6() && filter.srcPrefixLength > 32)))
        throw cRuntimeError("srcPrefixLength is invalid");
    if (!filter.destAddr.isUnspecified() && ((filter.destAddr.isIPv6() && filter.destPrefixLength > 128) ||
                                             (!filter.destAddr.isIPv6() && filter.destPrefixLength > 32)))
        throw cRuntimeError("srcPrefixLength is invalid");
    if (filter.protocol != -1 && (filter.protocol < 0 || filter.protocol > 0xff))
        throw cRuntimeError("protocol is not a valid protocol number");
    if (filter.tos != -1 && (filter.tos < 0 || filter.tos > 0xff))
        throw cRuntimeError("tos is not valid");
    if (filter.tosMask < 0 || filter.tosMask > 0xff)
        throw cRuntimeError("tosMask is not valid");
    if (filter.srcPortMin != -1 && (filter.srcPortMin < 0 || filter.srcPortMin > 0xffff))
        throw cRuntimeError("srcPortMin is not a valid port number");
    if (filter.srcPortMax != -1 && (filter.srcPortMax < 0 || filter.srcPortMax > 0xffff))
        throw cRuntimeError("srcPortMax is not a valid port number");
    if (filter.srcPortMin != -1 && filter.srcPortMin > filter.srcPortMax)
        throw cRuntimeError("srcPortMin > srcPortMax");
    if (filter.destPortMin != -1 && (filter.destPortMin < 0 || filter.destPortMin > 0xffff))
        throw cRuntimeError("destPortMin is not a valid port number");
    if (filter.destPortMax != -1 && (filter.destPortMax < 0 || filter.destPortMax > 0xffff))
        throw cRuntimeError("destPortMax is not a valid port number");
    if (filter.destPortMin != -1 && filter.destPortMin > filter.destPortMax)
        throw cRuntimeError("destPortMin > destPortMax");

    filters.push_back(filter);
}

void MFClassifier::configure(cXMLElement *config, cSimpleModule &owner)
{
    IPvXAddressResolver addressResolver;
    cXMLElementList filterElements = config->getChildrenByTagName("filter");
    for (int i = 0; i < (int)filterElements.size(); i++)
    {
        cXMLElement *filterElement = filterElements[i];
        try
        {
            const char *dscpAttr = filterElement->getAttribute("dscp");
            const char *srcAddrAttr = filterElement->getAttribute("srcAddress");
            const char *destAddrAttr = filterElement->getAttribute("destAddress");
            const char *protocolAttr = filterElement->getAttribute("protocol");
            const char *tosAttr = filterElement->getAttribute("tos");
            const char *tosMaskAttr = filterElement->getAttribute("tosMask");
            const char *srcPortAttr = filterElement->getAttribute("srcPort");
            const char *destPortAttr = filterElement->getAttribute("destPort");

            Filter filter;
            filter.dscp = parseDSCP(dscpAttr, "dscp");
            if (srcAddrAttr)
                filter.srcAddr = addressResolver.resolve(srcAddrAttr);
            // filter.srcPrefixLength =
            if (destAddrAttr)
                filter.destAddr = addressResolver.resolve(destAddrAttr);
            if (protocolAttr)
                filter.protocol = parseProtocol(protocolAttr, "protocol");
            if (tosAttr)
                filter.tos = parseIntAttribute(tosAttr, "tos");
            if (tosMaskAttr)
                filter.tosMask = parseIntAttribute(tosAttr, "tosMask");
            if (srcPortAttr)
                filter.srcPortMin = filter.srcPortMax = parseIntAttribute(srcPortAttr, "srcPort");
            if (destPortAttr)
                filter.destPortMin = filter.destPortMax = parseIntAttribute(destPortAttr, "destPort");


            addFilter(filter);
        }
        catch (std::exception& e)
        {
            throw cRuntimeError("Error in XML <filter> element at %s: %s", filterElement->getSourceLocation(), e.what());
        }
    }
}

