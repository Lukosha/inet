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


#ifndef __INET_TRAFFICCONDITIONER_H
#define __INET_TRAFFICCONDITIONER_H

#include <map>

#include "INETDefs.h"

#include "IDSCPClassifier.h"
#include "IMeter.h"
#include "ITrafficShaper.h"

/**
 * This module performs traffic policing/conditioning of sent or received
 * packets at egde routers of a Diffserv domain. This module acts as a filter
 * of incoming or outgoing traffic of an interface.
 *
 * It can perform the following tasks:
 * - classify the packets into behaviour aggregates identified by a Diffserv code point (DSCP)
 * - meter the traffic of individual aggregates or a set of aggregates and decide if it conforms to a traffic policy
 * - drop/delay packets that are not conforming to the traffic policy
 * - mark packets with the appropriate DSCPs by setting the ToS/TrafficClass field of IP datagrams
 *
 * The module is composed of several smaller components:
 * - classifier does the classification
 * - meters are metering the traffic and define the allowed traffic profiles
 * - shapers are changing the temporal characteristic of the traffic to conform to the traffic profile (e.g. delaying packets)
 * These components can be implemented as C++ classes and configured by an XML file.
 *
 * Note, that this module does not implement queuing behaviour. For Diffserv compatible queueing, edge
 * and core nodes of a DS domain should use an DiffservQueue in their interface modules.
 */
class INET_API TrafficConditioner : public cSimpleModule
{
  protected:

    IDSCPClassifier *classifier;      // packet classifier
    std::map<std::string, IMeter*> meters; // set of meters, keyed by name
    IMeter* *dscpToMeterMap;          // array for assigning meters to code points (having DSCP_MAX elements)
    int numColors;                    // maximum number of colors used by meters
    typedef unsigned char ActionCode; // 0-63: mark, 64-127: mark and shape, 253 shape only, 254 drop, 255 dont change
    ActionCode *actions;              // array of action codes (having DSCP_MAX*numColors elements)
    std::map<std::pair<int,int>, ITrafficShaper*> shapers; // maps (dscp,color) to shaping action

    // encoding of actions
    static const int ShapeAction = 253;
    static const int DropAction = 254;
    static const int NopAction = 255;
    int MarkAction(int dscp) { return dscp; }
    int MarkAndShapeAction(int dscp) { return dscp | 0x40; }
    int DscpOfMarkAction(int action) { return action & 0x3f; }
    bool isMarkAction(ActionCode action) { return (action & 0x80) == 0; }
    bool isShapeAction(ActionCode action) { return (action & 0xc0) == 0x40 || action == ShapeAction; }

    // actions array access
    ActionCode getActionCode(int dscp, int color) { return actions ? actions[DSCP_MAX*color+dscp] : NopAction; }
    void setActionCode(int dscp, int color, ActionCode action) { actions[color*DSCP_MAX+dscp] = action; }

  public:
    TrafficConditioner();
    virtual ~TrafficConditioner();

  protected:
    virtual int numInitStages() const  {return 4;}

    virtual void initialize(int stage);

    virtual void handleMessage(cMessage *msg);

    virtual int classifyPacket(cPacket *packet);

    virtual cPacket *conditionPacket(cPacket *packet, int dscp);

    virtual int meterPacket(cPacket *packet, int dscp);

    virtual void markPacket(cPacket *packet, int dscp);

    virtual void dropPacket(cPacket *packet, int dscp, int color);

    virtual cPacket *shapePacket(cPacket *packet, int dscp, int color);
};

#endif
