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
#include "IMeter.h"
#include "DiffservUtil.h"

using namespace DiffservUtil;

/**
 * Simple token bucket meter.
 */
class INET_API TokenBucket : public IMeter
{
    protected:
        double CIR; // Commited Information Rate (bits/sec)
        long CBS;    // Committed Burst Size (in bits)

        long Tc; // token bucket for committed burst
        simtime_t lastUpdateTime;
    public:
        TokenBucket();
        virtual void configure(cXMLElement *config, cSimpleModule &owner);
        virtual int getNumberOfColors() const { return 2; }
        virtual int packetArrived(cPacket *packet);
};

Register_Class(TokenBucket);

TokenBucket::TokenBucket()
    : CIR(0), CBS(0), Tc(0)
{
    lastUpdateTime = simTime();
}

void TokenBucket::configure(cXMLElement *config, cSimpleModule &owner)
{
    const char *cirAttribute = config->getAttribute("cir");
    const char *cbsAttribute = config->getAttribute("cbs");
    CIR = parseInformationRate(cirAttribute, "cir", owner, 0);
    CBS = parseBucketSize(cbsAttribute, "cbs", owner, 0);
    Tc = CBS;
    lastUpdateTime = simTime();
}

int TokenBucket::packetArrived(cPacket *packet)
{
    // update token buckets
    simtime_t currentTime = simTime();
    long numTokens = (long)(SIMTIME_DBL(currentTime-lastUpdateTime) * CIR);
    if (Tc + numTokens <= CBS)
        Tc += numTokens;

    // update meter state
    lastUpdateTime = currentTime;
    int packetSizeInBits = 8 * packet->getByteLength();
    if (Tc - packetSizeInBits >= 0)
    {
        Tc -= packetSizeInBits;
        return GREEN;
    }
    else
        return RED;
}

/**
 * Single Rate Three Color Marker.
 * This class can be used as a meter in the TrafficConditioner.
 * It marks the packets according to three parameters,
 * Committed Information Rate (CIR), Committed Burst Size (CBS),
 * and Excess Burst Size (EBS), to be either green, yellow or red.
 *
 * See RFC 2697.
 */
class INET_API SRTCM : public IMeter
{
  protected:
    double CIR; // Commited Information Rate (bits/sec)
    long CBS; // Committed Burst Size (bits)
    long EBS; // Excess Burst Size (bits)

    long Tc; // token bucket for committed burst
    long Te; // token bucket for excess burst
    simtime_t lastUpdateTime;
  public:
    SRTCM();
    virtual void configure(cXMLElement *config, cSimpleModule &owner);
    virtual int getNumberOfColors() const { return 3; }
    virtual int packetArrived(cPacket *packet);
};

Register_Class(SRTCM);

SRTCM::SRTCM()
    : CIR(0), CBS(0), EBS(0), Tc(0), Te(0)
{
    lastUpdateTime = simTime();
}

void SRTCM::configure(cXMLElement *config, cSimpleModule &owner)
{
    const char *cirAttribute = config->getAttribute("cir");
    const char *cbsAttribute = config->getAttribute("cbs");
    const char *ebsAttribute = config->getAttribute("ebs");
    CIR = parseInformationRate(cirAttribute, "cir", owner, 0);
    CBS = parseBucketSize(cbsAttribute, "cbs", owner, 0);
    EBS = parseBucketSize(ebsAttribute, "ebs", owner, 0);
    Tc = CBS;
    Te = EBS;
    lastUpdateTime = simTime();
}

int SRTCM::packetArrived(cPacket *packet)
{
    // update token buckets
    simtime_t currentTime = simTime();
    long numTokens = (long)(SIMTIME_DBL(currentTime-lastUpdateTime) * CIR);
    if (Tc + numTokens <= CBS)
        Tc += numTokens;
    else
    {
        long excessTokens = Tc + numTokens - CBS;
        Tc = CBS;
        if (Te + excessTokens <= EBS)
            Te += excessTokens;
        else
            Te = EBS;
    }

    // update meter state
    lastUpdateTime = currentTime;
    int packetSizeInBits = 8 * packet->getByteLength();
    if (Tc - packetSizeInBits >= 0)
    {
        Tc -= packetSizeInBits;
        return GREEN;
    }
    else if (Te - packetSizeInBits >= 0)
    {
        Te -= packetSizeInBits;
        return YELLOW;
    }
    else
        return RED;
}

/**
 * Two Rate Three Color Marker.
 * This class can be used as a meter in the TrafficConditioner.
 * It marks the packets based on two rates, Peak Information Rate (PIR)
 * and Committed Information Rate (CIR), and their associated burst sizes
 * to be either green, yellow or red.
 *
 * See RFC 2698.
 */
class INET_API TRTCM : public IMeter
{
  protected:
    double PIR; // Peak Information Rate (bits/sec)
    long PBS; // Peak Burst Size (bits)
    double CIR; // Committed Information Rate (bit/sec)
    long CBS; // Committed Burst Size (bits)

    long Tp; // token bucket for peak burst
    long Tc; // token bucket for comitted burst
    simtime_t lastUpdateTime;
  public:
    TRTCM();
    virtual void configure(cXMLElement *config, cSimpleModule &owner);
    virtual int getNumberOfColors() const { return 3; }
    virtual int packetArrived(cPacket *packet);
};

Register_Class(TRTCM);

TRTCM::TRTCM()
    : PIR(0), PBS(0), CIR(0), CBS(0), Tp(0), Tc(0)
{
    lastUpdateTime = simTime();
}

void TRTCM::configure(cXMLElement *config, cSimpleModule &owner)
{
    const char *pirAttribute = config->getAttribute("pir");
    const char *pbsAttribute = config->getAttribute("pbs");
    const char *cirAttribute = config->getAttribute("cir");
    const char *cbsAttribute = config->getAttribute("cbs");
    PIR = parseInformationRate(pirAttribute, "pir", owner, 0);
    PBS = parseBucketSize(pbsAttribute, "pbs", owner, 0);
    CIR = parseInformationRate(cirAttribute, "cir", owner, 0);
    CBS = parseBucketSize(cbsAttribute, "cbs", owner, 0);
    Tp = PBS;
    Tc = CBS;
    lastUpdateTime = simTime();
}

int TRTCM::packetArrived(cPacket *packet)
{
    // update token buckets
    simtime_t currentTime = simTime();
    double elapsedTime = SIMTIME_DBL(currentTime - lastUpdateTime);
    long numTokens = (long)(elapsedTime * PIR);
    if (Tp + numTokens <= PBS)
        Tp += numTokens;
    else
        Tp = PBS;
    numTokens = (long)(elapsedTime * CIR);
    if (Tc + numTokens <= CBS)
        Tc += numTokens;
    else
        Tc = CBS;

    // update meter state
    lastUpdateTime = currentTime;
    int packetSizeInBits = 8 * packet->getByteLength();
    if (Tp - packetSizeInBits < 0)
    {
        return RED;
    }
    else if (Tc - packetSizeInBits < 0)
    {
        Tp -= packetSizeInBits;
        return YELLOW;
    }
    else
    {
        Tp -= packetSizeInBits;
        Tc -= packetSizeInBits;
        return GREEN;
    }
}

