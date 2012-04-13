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

#include <utility>

#ifdef WITH_IPv4
#include "IPv4Datagram.h"
#endif

#ifdef WITH_IPv6
#include "IPv6Datagram.h"
#endif

#include "TrafficConditioner.h"
#include "DiffservUtil.h"

using namespace DiffservUtil;

Define_Module(TrafficConditioner);

TrafficConditioner::TrafficConditioner()
    : classifier(NULL), dscpToMeterMap(NULL), numColors(0), actions(NULL)
{
}

TrafficConditioner::~TrafficConditioner()
{
    delete classifier;

    for (std::map<std::string, IMeter*>::iterator it = meters.begin(); it != meters.end(); ++it)
        delete it->second;
    meters.clear();

    delete[] dscpToMeterMap;

    delete[] actions;

    for (std::map<std::pair<int,int>, ITrafficShaper*>::iterator it = shapers.begin(); it != shapers.end(); ++it)
        delete it->second;
    shapers.clear();
}

// set classifier, meters, markers, droppers, shapers
void TrafficConditioner::initialize(int stage)
{
    if (stage != 3)
        return;

    cXMLElement *config = par("config").xmlValue();
    cXMLElement *currentElement = config;

    try
    {
        // create classifier
        cXMLElement *classifierConfig = config->getFirstChildWithTag("classifier");
        if (classifierConfig)
        {
            currentElement = classifierConfig;
            const char *classifierType = classifierConfig->getAttribute("type");
            if (!classifierType)
                classifierType = "MFClassifier";
            classifier = check_and_cast<IDSCPClassifier*>(createOne(classifierType));
            classifier->configure(classifierConfig, *this);
        }

        // create meters
        numColors = 1;
        cXMLElement *metersConfig = config->getFirstChildWithTag("meters");
        if (metersConfig)
        {
            cXMLElementList meterElements = metersConfig->getChildrenByTagName("meter");
            for (int i = 0; i < (int)meterElements.size(); ++i)
            {
                cXMLElement *meterElement = currentElement = meterElements[i];
                std::string name = getRequiredAttribute(meterElement, "name");
                if (meters.find(name) != meters.end())
                    throw cRuntimeError("meter named '%s' already defined", name.c_str());
                const char *type = getRequiredAttribute(meterElement, "type");
                IMeter *meter = check_and_cast<IMeter*>(createOne(type));
                meter->configure(meterElement, *this);
                meters[name] = meter;
                numColors = std::max(numColors, meter->getNumberOfColors());
            }

            // assign meters to DSCPs
            cXMLElementList profileElements = metersConfig->getChildrenByTagName("traffic-profile");
            if (!profileElements.empty())
            {
                dscpToMeterMap = new IMeter*[DSCP_MAX];
                for (int i = 0; i < DSCP_MAX; ++i)
                    dscpToMeterMap[i] = NULL;

                for (int i = 0; i < (int)profileElements.size(); ++i)
                {
                    cXMLElement *profileElement = currentElement = profileElements[i];
                    std::string meterName = getRequiredAttribute(profileElement, "meter");
                    std::map<std::string, IMeter*>::iterator it = meters.find(meterName);
                    if (it == meters.end())
                        throw cRuntimeError("meter named '%s' not found", meterName.c_str());
                    IMeter *meter = it->second;

                    const char *dscpAttr = profileElement->getAttribute("dscp");
                    if (dscpAttr)
                    {
                        cStringTokenizer tokens(dscpAttr);
                        while (tokens.hasMoreTokens())
                        {
                            int dscp = parseDSCP(tokens.nextToken(), "dscp");
                            ASSERT(0 <= dscp && dscp <= DSCP_MAX);
                            dscpToMeterMap[dscp] = meter;
                        }
                    }
                    else
                    {
                        for (int j = 0; i < DSCP_MAX; ++j)
                            dscpToMeterMap[j] = meter;
                    }
                }
            }
        }

        cXMLElement *actionsConfig = config->getFirstChildWithTag("actions");
        if (actionsConfig)
        {
            // create markers/droppers/shapers
            actions = new unsigned char[DSCP_MAX * numColors];
            for (int dscp = 0; dscp < DSCP_MAX; ++dscp)
                for (int color = 0; color < numColors; ++color)
                    setActionCode(dscp, color, NopAction);

            cXMLElementList actionElements = actionsConfig->getChildren();
            for (int i = 0; i < (int)actionElements.size(); ++i)
            {
                cXMLElement *actionElement = currentElement = actionElements[i];
                const char *actionName = actionElement->getTagName();
                const char *dscpAttr = actionElement->getAttribute("dscp");
                const char *colorAttr = actionElement->getAttribute("color");
                std::vector<int> mathcingDSCPs;
                parseDSCPs(isEmpty(dscpAttr) ? "*" : dscpAttr, "dscp", mathcingDSCPs);
                std::vector<int> matchingColors;
                parseColors(isEmpty(colorAttr) ? "*" : colorAttr, "color", numColors, matchingColors);

                if (!strcmp(actionName, "drop"))
                {
                    for (int j = 0; j < (int)mathcingDSCPs.size(); ++j)
                        for (int k = 0; k < (int)matchingColors.size(); ++k)
                            setActionCode(mathcingDSCPs[j], matchingColors[k], DropAction);
                }
                else if (!strcmp(actionName, "mark"))
                {
                    const char *valueAttr = getRequiredAttribute(actionElement, "value");
                    int value = !strcmp(valueAttr, "*") ? -1 : parseDSCP(valueAttr, "value");

                    for (int j = 0; j < (int)mathcingDSCPs.size(); ++j)
                    {
                        int dscp = value != -1 ? value : mathcingDSCPs[j];
                        for (int k = 0; k < (int)matchingColors.size(); ++k)
                        {
                            ActionCode action = getActionCode(mathcingDSCPs[j], matchingColors[k]);
                            if (action == NopAction)
                                setActionCode(mathcingDSCPs[j], matchingColors[k], MarkAction(dscp));
                            else if (action == ShapeAction)
                                setActionCode(mathcingDSCPs[j], matchingColors[k], MarkAndShapeAction(dscp));
                        }
                    }
                }
                else if (!strcmp(actionName, "shape"))
                {
                    const char *typeAttr = getRequiredAttribute(actionElement, "type");
                    for (int j = 0; j < (int)mathcingDSCPs.size(); ++j)
                    {
                        for (int k = 0; k < (int)matchingColors.size(); ++k)
                        {
                            ActionCode action = getActionCode(mathcingDSCPs[j], matchingColors[k]);
                            if (action == NopAction)
                                setActionCode(mathcingDSCPs[j], matchingColors[k], ShapeAction);
                            else if (isMarkAction(action))
                                setActionCode(mathcingDSCPs[j], matchingColors[k], MarkAndShapeAction(DscpOfMarkAction(action)));

                            ITrafficShaper *shaper = check_and_cast<ITrafficShaper*>(createOne(typeAttr));
                            shaper->configure(actionElement, *this);
                            shapers[std::make_pair(mathcingDSCPs[j], matchingColors[k])] = shaper;
                        }
                    }
                }
            }
        }
    }
    catch (std::exception& e)
    {
        if (currentElement)
            throw cRuntimeError("Error in XML config file in <%s> element at %s: %s",
                    currentElement->getTagName(), currentElement->getSourceLocation(), e.what());
        else
            throw cRuntimeError("Error in XML config file: %s", e.what());
    }
}

void TrafficConditioner::handleMessage(cMessage *msg)
{
    cPacket *packet = dynamic_cast<cPacket*>(msg);
    if (packet)
    {
        int dscp = classifyPacket(packet);
        cPacket *pkt = conditionPacket(packet, dscp);
        if (pkt)
            send(pkt, "out");
    }
}

int TrafficConditioner::classifyPacket(cPacket *packet)
{
    return classifier ? classifier->classifyPacket(packet) : DSCP_BE;
}

cPacket *TrafficConditioner::conditionPacket(cPacket *packet, int dscp)
{
    int color = meterPacket(packet, dscp);
    ActionCode action = getActionCode(dscp, color);
    if (action == NopAction)
    {
        return packet;
    }
    else if (action == DropAction)
    {
        dropPacket(packet, dscp, color);
        return NULL;
    }
    else if (isMarkAction(action))
    {
        dscp = DscpOfMarkAction(action);
        markPacket(packet, dscp);
    }

    return isShapeAction(action) ? shapePacket(packet, dscp, color) : packet;
}

int TrafficConditioner::meterPacket(cPacket *packet, int dscp)
{
    ASSERT(0 <= dscp && dscp < DSCP_MAX);
    EV << "Metering packet (dscp=" << dscpToString(dscp) << "): ";
    IMeter *meter = dscpToMeterMap ? dscpToMeterMap[dscp] : NULL;
    int color = meter ? meter->packetArrived(packet) : IMeter::GREEN;
    EV << colorToString(color) << "\n";
    return color;
}

void TrafficConditioner::dropPacket(cPacket *packet, int dscp, int color)
{
    EV << "Dropping packet (dscp=" << dscpToString(dscp) << ", color=" << colorToString(color) << ")\n";

    // TODO statistics
    delete packet;
}

void TrafficConditioner::markPacket(cPacket *packet, int dscp)
{
    EV << "Marking packet with dscp=" << dscpToString(dscp) << "\n";

#ifdef WITH_IPv4
    if (dynamic_cast<IPv4Datagram *>(packet))
    {
        IPv4Datagram *datagram = (IPv4Datagram *)packet;
        datagram->setTypeOfService(dscp);  // DSCP is the six least significant bits of ToS
    }
    else
#endif
#ifdef WITH_IPv6
    if (dynamic_cast<IPv6Datagram *>(packet))
    {
        IPv6Datagram *datagram = (IPv6Datagram *)packet;
        datagram->setTrafficClass(dscp); // DSCP is the six least significant bits of Traffic Class
    }
    else
#endif
    {
        // nop
    }
}

cPacket *TrafficConditioner::shapePacket(cPacket *packet, int dscp, int color)
{
    ASSERT(0 <= dscp && dscp < DSCP_MAX);
    ASSERT(0 <= color && color < numColors);
    EV << "Shaping packet (dscp=" << dscpToString(dscp) << ", color=" << colorToString(color) << ")\n";
    std::pair<int,int> key = std::make_pair(dscp, color);
    std::map<std::pair<int, int>, ITrafficShaper*>::iterator it = shapers.find(key);
    if (it != shapers.end())
        return it->second->shapePacket(packet);
    else
        return packet;
}
