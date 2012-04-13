//
// Copyright (C) 2005 Andras Varga
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


#ifndef __INET_IDSCPCLASSIFIER_H
#define __INET_IDSCPCLASSIFIER_H

#include "INETDefs.h"
#include "DSCP_m.h"

/**
 * Used by Diffserv capable routers to classify the traffic.
 */
class INET_API IDSCPClassifier : public cObject
{
  public:
    /**
     * Sets the parameters of this classifiers.
     * This method is called at initialization after the interfaces got initialized.
     */
    virtual void configure(cXMLElement *config, cSimpleModule &owner) {}

    /**
     * Returns a Diffserv code point for the received packet.
     * One possible implementation is simply return the codepoint
     * read from the TypeOfService or TrafficClass field of the datagram.
     *
     * Result must be an integer between 0 and 63.
     * Standard code points are defined in DSCP.msg.
     */
    virtual int classifyPacket(cPacket *msg) = 0;
};

#endif

