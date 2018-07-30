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

import java.nio.ByteBuffer
import java.time.{Duration, Instant}
import java.util

import com.punchcyber.pakhet.datatypes.packet.{IpPacketRecord, PacketFeatureStat}
import com.punchcyber.pakhet.utils.GeneralUtils.sortAndStringify
import org.apache.commons.lang3.SerializationUtils
import org.apache.hadoop.hbase.client.Put
import org.apache.hadoop.hbase.util.Bytes

import scala.collection.mutable.ListBuffer
import scala.collection.parallel.mutable.ParHashMap

@SerialVersionUID(101010L)
class IpPacketSummary(timeout:        Float,
                      packetRecord:   IpPacketRecord) extends AbstractPacketSummary with Serializable {
    /**/
    val reference: String = packetRecord.reference
    val sensor: String = packetRecord.sensor
    val record_buffer: util.TreeSet[IpPacketRecord] = {
        val t: util.TreeSet[IpPacketRecord] = new util.TreeSet[IpPacketRecord]()
        t.add(packetRecord)
        t
    }
    var id_orig_h: String = packetRecord.id_orig_h
    var id_resp_h: String = packetRecord.id_resp_h
    val ip_version: String = packetRecord.ip_version
    val ip_key: String = s"|$reference|$sensor" + sortAndStringify(id_orig_h,id_resp_h)
    val ip_port_key: String = ip_key
    override val byte_count: ParHashMap[String, Float] = ParHashMap[String,Float](packetRecord.id_orig_h -> packetRecord.bytes,packetRecord.id_resp_h -> 0F)
    override val packet_count: ParHashMap[String, Float] = ParHashMap[String,Float](packetRecord.id_orig_h -> 1F,packetRecord.id_resp_h -> 0F)
    override val protocol: String = packetRecord.protocol
    override val source_row_key: String = packetRecord.source_file
    
    // Add our first tuple to ack later
    //storm_tuples += tuple.getMessageId.toString
    
    override def get_row_key: String = { Array(reference,sensor,id_orig_h,id_resp_h,protocol,record_buffer.first.ts.getEpochSecond,record_buffer.first.ts.getNano,frame_uid).mkString("|") }
    
    override def is_ready: Boolean = {
        // Timeout based on wire time
        if(Duration.between(record_buffer.first.ts,record_buffer.last.ts).toMillis > timeout.toLong) {
            true
        }
        // timeout in "real" time
        else if(Duration.between(last_written_to,Instant.now()).toMillis > 5000L) {
            true
        }
        else {
            false
        }
    }
    
    // We can only go off of which IP was seen sending data first, perhaps there will be another way later?
    def add_packet(record: IpPacketRecord/*,_tuple: Tuple*/): Option[IpPacketRecord] = {
        //storm_tuples += _tuple.getMessageId.toString
        packet_count(record.id_orig_h) += 1F
        byte_count(record.id_orig_h) += record.bytes
        record_buffer.add(record)
        last_written_to = Instant.now()
        None
    }
    
    override def getHBaseTableName: String = f"$reference-packets"
    
    override def getHBasePut: Put = {
        val t1: Instant = record_buffer.first.ts
        val t2: Instant = record_buffer.last.ts
        val ts1: ByteBuffer = ByteBuffer.allocate(12)
        ts1.putLong(0,t1.toEpochMilli)
        ts1.putInt(8,t1.getNano)
        val ts2: ByteBuffer = ByteBuffer.allocate(12)
        ts2.putLong(0,t2.toEpochMilli)
        ts2.putInt(8,t2.getNano)
        
        val first_packet: IpPacketRecord = record_buffer.first
        var src_bytes: Float = byte_count(id_orig_h)
        var dst_bytes: Float = byte_count(id_resp_h)
        var src_pkts: Float = packet_count(id_orig_h)
        var dst_pkts: Float = packet_count(id_resp_h)
        
        if(first_packet.id_orig_h != id_orig_h) {
            id_orig_h = first_packet.id_orig_h
            id_resp_h = first_packet.id_resp_h
            src_bytes = byte_count(id_orig_h)
            dst_bytes = byte_count(id_resp_h)
            src_pkts = packet_count(id_orig_h)
            dst_pkts = packet_count(id_resp_h)
        }
        
        val put: Put = new Put(Bytes.toBytes(get_row_key),t1.toEpochMilli)
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS"),ts1.array())
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS_END"),ts2.array())
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS_DURATION"),Bytes.toBytes(Duration.between(t1,t2).toNanos.toFloat / 1000000000.0F))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS_NANOS"),Bytes.toBytes(t1.getNano))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("REFERENCE"),Bytes.toBytes(reference))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("SENSOR"),Bytes.toBytes(sensor))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_ORIG_H"),Bytes.toBytes(id_orig_h))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_RESP_H"),Bytes.toBytes(id_resp_h))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("IP_VERSION"),Bytes.toBytes(ip_version))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("PROTO"),Bytes.toBytes(protocol))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ORIG_BYTES"),Bytes.toBytes(src_bytes))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("RESP_BYTES"),Bytes.toBytes(dst_bytes))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ORIG_PKTS"),Bytes.toBytes(src_pkts))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("RESP_PKTS"),Bytes.toBytes(dst_pkts))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("SOURCE_FILE"),Bytes.toBytes(source_row_key))
        
        val buffer: ListBuffer[Float] = new ListBuffer[Float]()
        val iter: util.Iterator[IpPacketRecord] = record_buffer.iterator()
        while(iter.hasNext) {
            val packet: IpPacketRecord = iter.next
            put.addColumn(Bytes.toBytes("PLD"),Bytes.toBytes(packet.row_key),SerializationUtils.serialize(packet))
            buffer += packet.bytes
        }
        
        if(buffer.lengthCompare(1) > 0) {
            val packetStats: PacketFeatureStat = new PacketFeatureStat(buffer.toArray)
            put.addColumn(Bytes.toBytes("PM"),Bytes.toBytes("BYTES_MIN"),Bytes.toBytes(packetStats.min))
            put.addColumn(Bytes.toBytes("PM"),Bytes.toBytes("BYTES_MEAN"),Bytes.toBytes(packetStats.mean))
            put.addColumn(Bytes.toBytes("PM"),Bytes.toBytes("BYTES_MEDIAN"),Bytes.toBytes(packetStats.median))
            put.addColumn(Bytes.toBytes("PM"),Bytes.toBytes("BYTES_MAX"),Bytes.toBytes(packetStats.max))
            put.addColumn(Bytes.toBytes("PM"),Bytes.toBytes("BYTES_STD_DEV"),Bytes.toBytes(packetStats.std_dev))
        }
        
        put
    }
    
    
}
