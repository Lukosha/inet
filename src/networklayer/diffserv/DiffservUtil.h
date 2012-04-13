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


#ifndef __INET_DIFFSERVQUEUE_H
#define __INET_DIFFSERVQUEUE_H

#include "INETDefs.h"

namespace DiffservUtil
{
    /**
     * Returns true, if the string is empty (NULL or "");
     */
    inline bool isEmpty(const char *str) { return !str || !(*str); }

    /**
     * Returns the value of the named attribute of the XML element,
     * or throws an exception if not found.
     */
    const char *getRequiredAttribute(cXMLElement *element, const char *attrName);

    /**
     * Parses the information rate parameter (bits/sec).
     * Supported formats:
     *  - absolute (e.g. 10Mbps)
     *  - relative to the datarate of the interface (e.g. 10%)
     */
    double parseInformationRate(const char *attrValue, const char *attrName, cSimpleModule &owner, int defaultValue);

    /**
     * Parses the bucket size parameter and returns the result in bits.
     */
    long parseBucketSize(const char *attrValue, const char *attrName, cSimpleModule &owner, int defaultValue);

    /**
     * Parses an integer attribute.
     * Supports decimal, octal ("0" prefix), hexadecimal ("0x" prefix), and binary ("0b" prefix) bases.
     */
    int parseIntAttribute(const char *attrValue, const char *attrName, bool isOptional = true);

    /**
     * Parses an IP protocol number.
     * Recognizes the names defined in IPProtocolId.msg (e.g. "UDP", "udp", "Tcp"),
     * and accepts decimal/octal/hex/binary numbers.
     */
    int parseProtocol(const char *attrValue, const char *attrName);

    /**
     * Parses a Diffserv code point.
     * Recognizes the names defined in DSCP.msg (e.g. "BE", "AF11"),
     * and accepts decimal/octal/hex/binary numbers.
     */
    int parseDSCP(const char *attrValue, const char *attrName);

    /**
     * Parses a space separated list of DSCP values and puts them into the result vector.
     * "*" is interpreted as all possible DSCP values (i.e. the 0..63 range).
     */
    void parseDSCPs(const char *attrValue, const char *attrName, std::vector<int> &result);

    /**
     * Parses a color value.
     * Recognizes the names defined in IMeter.h (e.g. "red", "Yellow", "GREEN"),
     * and accepts decimal/octal/hex/binary numbers.
     */
    int parseColor(const char *attrValue, const char *attrName);

    /**
     * Parses a space separated list of colors and puts them into the result vector.
     * "*" is interpreted as all colors in the 0..numColors-1 range.
     */
    void parseColors(const char *attrValue, const char *attrName, int numColors, std::vector<int> &result);

    /**
     * Returns the string representation of the given DSCP value.
     * Values defined in DSCP.msg are returned as "BE", "AF11", etc.,
     * others are returned as a decimal number.
     */
    std::string dscpToString(int dscp);

    /**
     * Returns the string representation of the given color.
     * For values defined in IMeter.h it returns their name,
     * other values are returned as decimal constants.
     */
    std::string colorToString(int color);

    /**
     * Returns the datarate of the interface containing the given module.
     * Returns -1, if the interface entry not found.
     */
    double getInterfaceDatarate(cSimpleModule *interfaceModule);
}
#endif
