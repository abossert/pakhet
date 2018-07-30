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

import java.nio.ByteBuffer
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util

import com.punchcyber.pakhet.datatypes.metric.InfluxMetric
import com.punchcyber.pakhet.utils.GeneralUtils.sortAndStringify
import org.apache.commons.lang3.SerializationUtils
import org.apache.hadoop.hbase.client.Put
import org.apache.hadoop.hbase.util.Bytes
import org.pcap4j.core.PcapHandle.TimestampPrecision
import org.pcap4j.core.PcapPacket
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.namednumber.DataLinkType

import scala.collection.mutable.ArrayBuffer

class UdpPacketRecord(prec:       TimestampPrecision,
                      dlt:        DataLinkType  = DataLinkType.LINUX_SLL,
                      fileRowKey: String,
                      packet:     PcapPacket,
                      ref:        String,
                      sens:       String = "") extends IpPacketRecord(prec,dlt,fileRowKey,packet,ref,sens) {
    /**/
    override val bytes: Float = {
        try {
            packet.get(classOf[UdpPacket]).getPayload.length()
        } catch {
            case _:NullPointerException => 0.0F
        }
    }
    val id_orig_p: Int = packet.get(classOf[UdpPacket]).getHeader.getSrcPort.valueAsInt
    val id_resp_p: Int = packet.get(classOf[UdpPacket]).getHeader.getDstPort.valueAsInt
    val service: String = {
        if(id_orig_p < id_resp_p) packet.get(classOf[UdpPacket]).getHeader.getSrcPort.name.toLowerCase.replaceAll("\\s+","_")
        else packet.get(classOf[UdpPacket]).getHeader.getDstPort.name.toLowerCase.replaceAll("\\s+","_")
    }
    override val row_key: String = Array(ref,sensor,id_orig_h,id_resp_h,id_orig_p,id_resp_p,protocol,ts.getEpochSecond,ts.getNano,bytes,frame_uid).mkString("|")
    override val ip_port_key: String = ip_key + sortAndStringify(id_orig_p,id_resp_p)
    
    override def getHBasePut: Put = {
        val t1: ByteBuffer = ByteBuffer.allocate(12)
        t1.putLong(0,ts.toEpochMilli)
        t1.putInt(8,ts.getNano)
        
        new Put(Bytes.toBytes(row_key),ts.toEpochMilli)
            .addColumn(Bytes.toBytes("PLD"),Bytes.toBytes("PACKET"),SerializationUtils.serialize(packet))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS"),t1.array())
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS_NANOS"),Bytes.toBytes(ts.getNano))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("REFERENCE"),Bytes.toBytes(reference))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("SENSOR"),Bytes.toBytes(sensor))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_ORIG_H"),Bytes.toBytes(id_orig_h))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_ORIG_P"),Bytes.toBytes(id_orig_p))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_RESP_H"),Bytes.toBytes(id_resp_h))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_RESP_P"),Bytes.toBytes(id_resp_p))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("SERVICE_NAME"),Bytes.toBytes(service))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("IP_VERSION"),Bytes.toBytes(ip_version))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("PROTO"),Bytes.toBytes(protocol))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("BYTES"),Bytes.toBytes(bytes))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("SOURCE_FILE"),Bytes.toBytes(source_file))
    }
    
    override def build_from_packet(_database: String,
                                   _retention_policy: String,
                                   _truncate_to: ChronoUnit,
                                   _timeout: Long,
                                   _timeoutUnit: ChronoUnit): Array[InfluxMetric] = {
        
        val timestamp: Instant = ts.truncatedTo(_truncate_to)
        val metric_array: ArrayBuffer[InfluxMetric] = ArrayBuffer[InfluxMetric]()
        
        for((measurement,fieldname) <- Array(
            ("ip_version",ip_version),
            ("protocol",protocol),
            ("service",service))) {
            
            val metric: InfluxMetric = new InfluxMetric(_database,_retention_policy,measurement,timestamp,_truncate_to,_timeout,_timeoutUnit)
            
            val tagMap: util.HashMap[String,String] = new util.HashMap[String,String]()
            tagMap.put("reference",reference)
            tagMap.put("sensor",sensor)
            tagMap.put(measurement,fieldname)
            metric.add_tag(tagMap)
            
            val fieldMap: util.HashMap[String,AnyRef] = new util.HashMap[String,AnyRef]()
            fieldMap.put("packets",1D:java.lang.Double)
            fieldMap.put("bytes",java.lang.Double.valueOf(bytes.toDouble))
            metric.add_field(fieldMap)
            metric.mtype = "PACKET"
            
            metric_array += metric
        }
        metric_array.toArray
    }
}
