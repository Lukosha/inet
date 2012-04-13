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


#include "INETDefs.h"
#include "IDSCPClassifier.h"

#ifdef WITH_IPv4
#include "IPv4Datagram.h"
#endif

#ifdef WITH_IPv6
#include "IPv6Datagram.h"
#endif


/**
 * Behaviour Aggregate Classifier (RFC 2475 2.3.1).
 *
 * This classifier reads to DSCP from the TypeOfService (IPv4)
 * or the TrafficClass (IPv6) field from the IP datagram.
 * Other packets are classified as BE (Best Effort).
 */
class INET_API BAClassifier : public IDSCPClassifier
{
  public:
    virtual int classifyPacket(cPacket *msg);
};


Register_Class(BAClassifier);

int BAClassifier::classifyPacket(cPacket *msg)
{
#ifdef WITH_IPv4
    if (dynamic_cast<IPv4Datagram *>(msg))
    {
        IPv4Datagram *datagram = (IPv4Datagram *)msg;
        return datagram->getTypeOfService() & 0x3f; // DSCP is the six least significant bits of ToS
    }
    else
#endif
#ifdef WITH_IPv6
    if (dynamic_cast<IPv6Datagram *>(msg))
    {
        IPv6Datagram *datagram = (IPv6Datagram *)msg;
        return datagram->getTrafficClass() & 0x3f; // DSCP is the six least significant bits of Traffic Class
    }
    else
#endif
    {
        return DSCP_BE; // lowest priority ("best effort")
    }
}
