/*
 * Copyright (c) 2018. Punch Cyber Analytics Group
 * All rights reserved.
 *
 * NOTICE: All information contained herein is the property of Punch Cyber Analytics Group.
 * The intellectual and technical concepts contained herein are proprietary to Punch Cyber
 * Analytics Group and may be covered by Patents and/or Patents in process in multiple
 * jurisdictions and as such, are protected by trade secret and/or copyright laws.
 *
 * Neither reproduction or dissemination of this material is permitted without prior written
 * permission from Punch Cyber Analytics Group
 */

package com.punchcyber.pakhet.datatypes.packet.summary

import java.time.Instant

import com.punchcyber.pakhet.datatypes.Pudable
import com.punchcyber.pakhet.datatypes.packet._
import org.pcap4j.packet._

import scala.collection.parallel.mutable.ParHashMap

/* TODO: prioritized list of Bro Conn Log fields to reproduce
 * Fields to import by priority:
 * DONE: 1-1 : conn_state
 * DONE: 1-2 : History (e.g. TCP flags)
 * 2-1 : orig/resp_l2_addr
 * ...
 * ...
 * 98  : tunnel_parents
 * 99  : vlan/inner_vlan */

@SerialVersionUID(101010L)
trait AbstractPacketSummary extends Pudable with Serializable {
    protected val frame_uid: String = java.util.UUID.randomUUID.toString
    protected val source_row_key: String
    protected val byte_count: ParHashMap[String,Float]
    protected val packet_count: ParHashMap[String,Float]
    protected val protocol: String
    protected var last_written_to: Instant = Instant.now()
    
    def is_ready: Boolean
    
    def get_row_key: String
    
    def get_total_bytes(addr1: String, addr2: String): Float = { byte_count(addr1) + byte_count(addr2) }
    
    def get_total_pkts(addr1: String, addr2: String): Float = { packet_count(addr1) + packet_count(addr2) }
}

object AbstractPacketSummary {
    def apply(timeout:        Float,
              packetRecord:   IpPacketRecord): IpPacketSummary = {
        
        if(packetRecord.get_pcap4j_packet.contains(classOf[TcpPacket]))                 { new TcpPacketSummary(timeout,packetRecord.asInstanceOf[TcpPacketRecord]) }
        else if(packetRecord.get_pcap4j_packet.contains(classOf[UdpPacket]))            { new UdpPacketSummary(timeout,packetRecord.asInstanceOf[UdpPacketRecord]) }
        else if(packetRecord.get_pcap4j_packet.contains(classOf[IcmpV4CommonPacket]) ||
                packetRecord.get_pcap4j_packet.contains(classOf[IcmpV6CommonPacket]))   { new IcmpPacketSummary(timeout,packetRecord.asInstanceOf[IcmpPacketRecord]) }
        else if(packetRecord.get_pcap4j_packet.contains(classOf[IpV4Packet]))           { new IpPacketSummary(timeout,packetRecord) }
        else { throw new UnsupportedProtocolException }
    }
}
