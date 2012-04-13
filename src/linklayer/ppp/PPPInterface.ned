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



package inet.linklayer.ppp;

import inet.networklayer.queue.IOutputQueue;
import inet.networklayer.diffserv.TrafficConditioner;
import inet.linklayer.IWiredNic;
import inet.base.IHook;


//
// PPP interface. Complements the ~PPP module with an output queue
// for QoS and RED support.
//
module PPPInterface like IWiredNic
{
    parameters:
        @display("i=block/ifcard;bgb=214,249;bgl=53");
        string queueType = default("DropTailQueue"); // DropTailQueue, DropTailQoSQueue, REDQueue, or empty for use internal queue
        bool isDiffservIngressInterface = default(false);
        bool isDiffservEgressInterface = default(false);
        int numOutputHooks = default(0);
        int numInputHooks = default(0);
    gates:
        input netwIn;
        output netwOut;
        inout phys @labels(PPPFrame);
    submodules:
        outputHook[numOutputHooks]: <default("Nop")> like IHook if numOutputHooks>0 {
            @display("p=42,33");
        }
        inputHook[numInputHooks]: <default("Nop")> like IHook if numInputHooks>0 {
            @display("p=177,33");
        }
        ingressTC: TrafficConditioner if isDiffservIngressInterface {
            @display("p=177,100");
        }
        egressTC: TrafficConditioner if isDiffservEgressInterface {
            @display("p=42,100");
        }
        queue: <queueType> like IOutputQueue if queueType != "" {
            parameters:
                @display("p=42,161;q=l2queue");
        }
        ppp: PPP {
            parameters:
                queueModule = (queueType == "" ? "" : "queue");
                txQueueLimit = (queueType == "" ? 10000 : 1); // queue sends one packet at a time
                @display("p=98,207");
        }
    connections:
        netwIn --> { @display("m=n"); } --> outputHook[0].in if numOutputHooks > 0;
        netwIn --> { @display("m=n"); } --> egressTC.in if numOutputHooks == 0 && isDiffservEgressInterface;
        netwIn --> { @display("m=n"); } --> queue.in if numOutputHooks == 0 && !isDiffservEgressInterface && queueType != "";
        netwIn --> { @display("m=n"); } --> ppp.netwIn if numOutputHooks == 0 && !isDiffservEgressInterface && queueType == "";

        egressTC.out --> queue.in if isDiffservEgressInterface && queueType != "";
        egressTC.out --> ppp.netwIn if isDiffservEgressInterface && queueType == "";

        for i=0..numOutputHooks-2 {
            outputHook[i].out --> outputHook[i+1].in;
        }
        outputHook[numOutputHooks-1].out --> egressTC.in if numOutputHooks > 0 && isDiffservEgressInterface;
        outputHook[numOutputHooks-1].out --> queue.in if numOutputHooks > 0 && !isDiffservEgressInterface && queueType != "";
        outputHook[numOutputHooks-1].out --> ppp.netwIn if numOutputHooks > 0 && !isDiffservEgressInterface && queueType == "";

        queue.out --> ppp.netwIn if queueType != "";

        phys <--> { @display("m=s"); } <--> ppp.phys;

        ppp.netwOut --> { @display("m=n"); } --> netwOut if numInputHooks == 0 && !isDiffservIngressInterface;

        ppp.netwOut --> ingressTC.in if isDiffservIngressInterface;
        ingressTC.out --> { @display("m=n"); } --> netwOut if isDiffservIngressInterface && numInputHooks == 0;

        ppp.netwOut --> inputHook[0].in if numInputHooks > 0 && !isDiffservIngressInterface;
        ingressTC.out --> inputHook[0].in if numInputHooks > 0 && isDiffservIngressInterface;

        for i=0..numInputHooks-2 {
            inputHook[i].out --> inputHook[i+1].in;
        }
        inputHook[numInputHooks-1].out --> { @display("m=n"); } --> netwOut if numInputHooks > 0;
}

