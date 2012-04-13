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


#ifndef __INET_IMETERING_H
#define __INET_IMETERING_H

#include "INETDefs.h"

/**
 * Interface of traffic metering components.
 * The meter observes the temporal characteristic of the incoming
 * packets and assign a conformance level to them.
 *
 * The conformance levels are usually named after colors:
 *  - green is conforming to the traffic profile of the meter
 *  - yellow is partially conforming
 *  - red is non-conforming.
 * Subclasses may use these colors and can define additional ones.
 * These conformance levels can trigger different marking, shaping,
 * queueing treatment of the colored packets.
 *
 */
class INET_API IMeter : public cObject
{
  public:

    /* Predefined colors.
     * (green=conformant, yellow=partially conformant, red=non-conformant)
     */
    enum Color {GREEN, YELLOW, RED};

    /**
     * Configure the parameters of this meter.
     */
    virtual void configure(cXMLElement *config, cSimpleModule &owner) {}

    /**
     * Returns the number of colors used by this meter.
     */
    virtual int getNumberOfColors() const = 0;

    /**
     * Meter the packet and returns its color.
     */
    virtual int packetArrived(cPacket *packet) = 0;
};

#endif
