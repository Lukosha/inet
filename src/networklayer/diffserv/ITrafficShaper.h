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


#ifndef __INET_ITRAFFICCONDITIONER_H
#define __INET_ITRAFFICCONDITIONER_H

#include "INETDefs.h"

/**
 * Interface of traffic shapers.
 * Traffic shapers change the temporal characteristic
 * of a traffic stream without changing individual packets
 * (e.g. delaying packets out of a traffic profile).
 *
 */
class INET_API ITrafficShaper : public cObject
{
  public:
     /**
      * Configures this traffic shaper.
      * This method is called at module initializion after
      * the initalization of interface modules.
      */
     virtual void configure(cXMLElement *config, cSimpleModule &owner) {};

     /**
      * Accepts a packet from the packet stream, and returns
      * one that is to be transmitted.
      * It returns either the packet it received, another one,
      * or NULL if no packet to be transmitted at the moment.
      */
     virtual cPacket *shapePacket(cPacket *packet) = 0;
};

#endif

