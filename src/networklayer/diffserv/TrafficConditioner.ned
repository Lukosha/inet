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

package inet.networklayer.diffserv;

//
// This module implements the policing and shaping actions
// of a Diffserv router. It should be added to the input
// or output path of interface modules of routers at the
// edge of the Diffserv Domain.
//
// The module performs the following actions:
//  - classify the incoming packets
//  - meter the traffic in each class
//  - marks/drops packets depending on the result of metering
//  - shape the traffic to conform to the desired traffic profile
//
// Note that queuing behaviour is not implemented by this module.
// There is a ~DiffservQueue module that can be used in edge and core
// routers to implement the per hop behaviours of DS classes. 
//
// The classifier, metering, and policing actions can be specified
// in an XML document given as the 'config' parameter. If the 'config'
// is not given, then the module has no effect, i.e. the traffic is
// not changed.
//
// <b>Classifier</b>
//
// The classifier component assign the DSCP value to the
// incoming packets based on the micro flow the packet belongs to.
// The default implementation of the classifier (MFClassifier)
// specifies the flows by a set of filter elements. Each filter
// can match the source and destination addresses, IP protocol
// number, source and destination ports, TypeOfService/TrafficClass
// field of the datagram. The first matching filter element
// determines the DSCP of the class.
//
// TODO: no matching filter --> BE (Best Effort)
// TODO: see ~DSCP message class for possible values
//
// TODO example
//
// <b>Meters</b>
//
// A meter can be to each class to measure the traffic.
// The meter assigns a conformance level to incoming packets.
// Different actions can be specified for class and conformance
// level to shape the traffic.
//
// Predefined conformance levels:
// - green: conformant traffic
// - yellow: partially conformant traffic
// - red: non-conformant traffic
//
// Currently three meters are implemented:
// 
// - TokenBucketMeter
//     Collects tokens in a bucket with a specified Committed
//     Information Rate (CIR). The capacity of the bucket is limited
//     by the Committed Burst Size (CBS). If a packet arrives, it
//     consumes as many tokens from the bucket as the length of the
//     packet. The packet is conformant (green) if there are enough tokens
//     in the bucket, non-conformant (red) otherwise.
// - SRTCM (Single Rate Three Color Marker, see RFC 2697)
//     It has a Commited Information Rate (CIR), and two
//     associated burst sizes: Committed Burst Size (CBS) and
//     Excess Burst Size (EBS). The packet is green
//     if it does not exceed the CBS; yellow if it does exceed
//     CBS, but not the EBS; red otherwise.
// - TRTCM (Two Rate Three Color Marker, see RFC 2698)
//     This meter has two information rate: Peak Information Rate (PIR)
//     and Committed Information Rate (CIR). A packet is red if it
//     exceeds the PIR; yellow if does not exceeds PIR, but exceeds CIR;
//     green otherwise.
//
// <b>Actions</b>
//
// The <actions> element specifies the traffic policing and conditioning
// actions. It may contain <drop>, <mark> or <shape> elements in its body.
//
// - <drop>
//     Drops matching packets unconditionally. It is applied to the packets
//     having the specified DS code point and color. The @dscp attribute
//     can be one or more DSCP value (either named or numeric), the color
//     is one or more color (also a named or numeric value). For example
//     the following element drops each red packet of the AF1x classes:
//
//     <pre>
//     <drop dscp="AF11 AF12 AF13" color="red"/>
//     </pre>
//      
// - <mark>
//     Sets the Type of Service (IPv4) or Traffic Class (IPv6) field
//     of the packet. It is applied to packets having the specified DSCP
//     and color. For example the following element marks packet classified
//     as EF, but non-comforming to the traffic policy as AF13.
//
//     <pre>
//     <mark dscp="EF" color="red" value="AF13"/>
//     </pre>
//
//     If no marker specified for a given packet, it will be marked
//     by the DSCP value assigned by the classifier.
//
// - <shape>
//     Shapes the traffic to conform to the specification, e.g. by
//     delaying non-conforming packets. There can be multiple shaper
//     implementations, the @type attribute specifies the implementation
//     class, other attributes are its parameters.
//     If both marker and shapers are specified for a given packet,
//     then the shaper is applied after the marker.
//
simple TrafficConditioner
{
    parameters:
        xml config= default(xml("<config/>")); // the XML configuration specifying the classifier, meter and shaping components
        @display("i=block/classifier");
    gates:
        input in;
        output out;
}
