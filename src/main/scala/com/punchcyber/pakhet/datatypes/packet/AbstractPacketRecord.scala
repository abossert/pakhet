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

package com.punchcyber.pakhet.datatypes.packet

import java.time.Instant
import java.time.temporal.ChronoUnit

import com.punchcyber.pakhet.datatypes.metric.InfluxMetric
import org.pcap4j.core.PcapHandle.TimestampPrecision
import org.pcap4j.core.PcapPacket
import org.pcap4j.packet._
import org.pcap4j.packet.namednumber.DataLinkType

@SerialVersionUID(101010L)
trait AbstractPacketRecord extends Serializable {
    /**/
    val frame_uid: String = java.util.UUID.randomUUID.toString
    val bytes: Float
    val row_key: String
    val source_file: String
    val ts: Instant
    
    def build_from_packet(_database: String,
                          _retention_policy: String,
                          _truncate_to: ChronoUnit,
                          _timeout: Long,
                          _timeoutUnit: ChronoUnit): Array[InfluxMetric]
    def get_pcap4j_packet: PcapPacket
}

object AbstractPacketRecord {
    def apply(prec:       TimestampPrecision,
              dlt:        DataLinkType  = DataLinkType.LINUX_SLL,
              fileRowKey: String,
              packet:     PcapPacket,
              ref:        String,
              sens:       String = ""): IpPacketRecord = {
        
        if(packet.contains(classOf[TcpPacket]))                 { new TcpPacketRecord(prec,dlt,fileRowKey,packet,ref,sens)  }
        else if(packet.contains(classOf[UdpPacket]))            { new UdpPacketRecord(prec,dlt,fileRowKey,packet,ref,sens)  }
        else if(packet.contains(classOf[IcmpV4CommonPacket]) ||
                packet.contains(classOf[IcmpV6CommonPacket]))   { new IcmpPacketRecord(prec,dlt,fileRowKey,packet,ref,sens) }
        else if(packet.contains(classOf[IpV4Packet]))           { new IpPacketRecord(prec,dlt,fileRowKey,packet,ref,sens)   }
        else { throw new UnsupportedProtocolException }
    }
}
