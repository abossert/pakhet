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
import java.time.temporal.ChronoUnit
import java.time.{Duration, Instant}
import java.util
import java.util.concurrent.ConcurrentHashMap

import com.punchcyber.pakhet.datatypes.packet._
import com.punchcyber.pakhet.utils.GeneralUtils.sortAndStringify
import org.apache.commons.lang3.SerializationUtils
import org.apache.hadoop.hbase.client.Put
import org.apache.hadoop.hbase.util.Bytes

import scala.collection.mutable.ListBuffer

class TcpPacketSummary(timeout:        Float,
                       /*tuple:          Tuple,*/
                       tcprecord:   TcpPacketRecord) extends IpPacketSummary(timeout/*,tuple*/,tcprecord) {
    
    private val first_packet_ts: Instant = tcprecord.ts
    private var last_packet_ts: Instant = tcprecord.ts
    
    var connection_state: conn_state = {
        if(tcprecord.Syn && !tcprecord.Ack) S0
        else if(tcprecord.Syn && tcprecord.Ack) S1
        else OTH
    }
    private var src_dst_set: Boolean = false
    var done: Boolean = false
    /* Setting initial "guess" for src and dst IP addresses based on first tcprecord.
     * If we have conclusively determined the src/dst, then set the src_dst_set
     * variable so we don't try to change it later.
     *
     * We are intentionally leaving the "dip" variable unset to avoid logic duplication.  Perhaps
     * we will rethink this later, but for now, set both SIP and DIP within the SIP assignment
     * function.
     *
     * Our strategy for determining the Bro connection state is to progressively change the state
     * as conditions change.  Thus, if we see a Syn, we set state to S0, if we then see a Syn-Ack,
     * we change to S1.  If, by the end of the session, we see a Fin, Fin-Ack, then we change to SF.
     */
    id_orig_h = {
        if(tcprecord.Syn && tcprecord.Ack) {
            src_dst_set = true
            id_resp_h = tcprecord.id_orig_h
            tcprecord.id_resp_h
        }
        else if(tcprecord.Syn) {
            src_dst_set = true
            id_resp_h = tcprecord.id_resp_h
            tcprecord.id_orig_h
        }
        else if(tcprecord.id_orig_p > tcprecord.id_resp_p) {
            src_dst_set = true
            id_resp_h = tcprecord.id_resp_h
            tcprecord.id_orig_h
        }
        else if(tcprecord.id_orig_p < tcprecord.id_resp_p) {
            src_dst_set = true
            id_resp_h = tcprecord.id_orig_h
            tcprecord.id_resp_h
        }
        // If we get here, then we are not sure who is who yet
        else {
            id_resp_h = tcprecord.id_resp_h
            tcprecord.id_orig_h
        }
    }
    val split_session: ConcurrentHashMap[String,util.concurrent.ConcurrentSkipListSet[TcpPacketRecord]] = {
        val tcp_session: ConcurrentHashMap[String,util.concurrent.ConcurrentSkipListSet[TcpPacketRecord]] = new ConcurrentHashMap[String,util.concurrent.ConcurrentSkipListSet[TcpPacketRecord]]()
        val set1: util.concurrent.ConcurrentSkipListSet[TcpPacketRecord] = new util.concurrent.ConcurrentSkipListSet[TcpPacketRecord]()
        val set2: util.concurrent.ConcurrentSkipListSet[TcpPacketRecord] = new util.concurrent.ConcurrentSkipListSet[TcpPacketRecord]()
        set1.add(tcprecord)
        tcp_session.put(tcprecord.id_orig_h,set1)
        tcp_session.put(tcprecord.id_resp_h,set2)
        tcp_session
    }
    val id_orig_p: Int = tcprecord.id_orig_p
    val id_resp_p: Int = tcprecord.id_resp_p
    val service: String = tcprecord.service
    override val ip_port_key: String = ip_key + sortAndStringify(id_orig_p,id_resp_p)
    
    override def get_row_key: String = { Array(reference,sensor,id_orig_h,id_resp_h,id_orig_p,id_resp_p,protocol,record_buffer.first.ts.getEpochSecond,record_buffer.first.ts.getNano,frame_uid).mkString("|") }
    
    def add_packet(this_packet: TcpPacketRecord/*,_tuple: Tuple*/): Option[TcpPacketSummary] = {
        //storm_tuples += _tuple.getMessageId.toString
        // Check for timeouts first, returning a new TcpSession
        if(first_packet_ts.until(this_packet.ts,ChronoUnit.MILLIS) > timeout ||
            last_packet_ts.until(this_packet.ts,ChronoUnit.SECONDS) > 3 ||
            last_written_to.until(Instant.now(),ChronoUnit.SECONDS) > 3) {
            
            // TODO: Need to revisit logic that says the session is "done" if we have hit a timeout
            done = true
            Some(new TcpPacketSummary(timeout/*,_tuple*/,this_packet))
        }
        else {
            // If we have not yet figured out who is who, keep trying
            if(!src_dst_set) {
                if(this_packet.Syn && this_packet.Ack) {
                    src_dst_set = true
                    id_orig_h = this_packet.id_resp_h
                    id_resp_h = this_packet.id_orig_h
                }
                else if(this_packet.Syn) {
                    src_dst_set = true
                    id_orig_h = this_packet.id_orig_h
                    id_resp_h = this_packet.id_resp_h
                }
                else if(this_packet.id_orig_p > this_packet.id_resp_p) {
                    src_dst_set = true
                    id_orig_h = this_packet.id_orig_h
                    id_resp_h = this_packet.id_resp_h
                }
                else if(this_packet.id_orig_p < this_packet.id_resp_p) {
                    src_dst_set = true
                    id_orig_h = this_packet.id_resp_h
                    id_resp_h = this_packet.id_orig_h
                }
                else if(this_packet.ack_num == 0L) {
                    src_dst_set = true
                    id_orig_h = this_packet.id_resp_h
                    id_resp_h = this_packet.id_orig_h
                }
                else if(this_packet.seq_num == 0L) {
                    src_dst_set = true
                    id_orig_h = this_packet.id_orig_h
                    id_resp_h = this_packet.id_resp_h
                }
            }
            
            if(this_packet.Syn && !this_packet.Ack) connection_state = S0
            else if(this_packet.Syn && this_packet.Ack) connection_state = S1
            else if(connection_state == S0 && this_packet.id_orig_h == id_orig_h && this_packet.Fin) connection_state = SH
            else if(Array[conn_state](S0,S1).contains(connection_state) && this_packet.Fin) connection_state = SF
            else if(connection_state == S0 && this_packet.id_orig_h == id_resp_h && this_packet.Rst) connection_state = REJ
            // TODO: S2 and S3 are not accounted for here
            else if(connection_state == S1 && this_packet.id_orig_h == id_orig_h && this_packet.Rst) connection_state = RSTO
            else if(connection_state == S1 && this_packet.id_orig_h == id_resp_h && this_packet.Rst) connection_state = RSTR
            else if(connection_state == S0 && this_packet.id_orig_h == id_orig_h && this_packet.Rst) connection_state = RSTOS0
            else if(connection_state == OTH && this_packet.id_orig_h == id_resp_h && this_packet.Rst) connection_state = RSTRH
            else if(connection_state == OTH && this_packet.Fin) connection_state = SHR
            
            split_session.get(this_packet.id_orig_h).add(this_packet)
            
            last_packet_ts = this_packet.ts
            last_written_to = Instant.now()
            packet_count(this_packet.id_orig_h) += 1F
            byte_count(this_packet.id_orig_h) += this_packet.bytes
            
            None
        }
    }
    
    override def getHBasePut: Put = {
        val t1: Instant = first_packet_ts
        val t2: Instant = last_packet_ts
        val ts1: ByteBuffer = ByteBuffer.allocate(12)
        ts1.putLong(0,t1.toEpochMilli)
        ts1.putInt(8,t1.getNano)
        val ts2: ByteBuffer = ByteBuffer.allocate(12)
        ts2.putLong(0,t2.toEpochMilli)
        ts2.putInt(8,t2.getNano)
        
        val src_bytes: Float = byte_count(id_orig_h)
        val dst_bytes: Float = byte_count(id_resp_h)
        val src_pkts: Float = packet_count(id_orig_h)
        val dst_pkts: Float = packet_count(id_resp_h)
        
        val put: Put = new Put(Bytes.toBytes(get_row_key),t1.toEpochMilli)
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS"),ts1.array())
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS_END"),ts2.array())
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS_DURATION"),Bytes.toBytes(Duration.between(t1,t2).toNanos.toFloat / 1000000000.0F))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("TS_NANOS"),Bytes.toBytes(t1.getNano))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("REFERENCE"),Bytes.toBytes(reference))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("SENSOR"),Bytes.toBytes(sensor))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_ORIG_H"),Bytes.toBytes(id_orig_h))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_RESP_H"),Bytes.toBytes(id_resp_h))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_ORIG_P"),Bytes.toBytes(id_orig_p))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ID_RESP_P"),Bytes.toBytes(id_resp_p))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("SERVICE"),Bytes.toBytes(service))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("IP_VERSION"),Bytes.toBytes(ip_version))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("PROTO"),Bytes.toBytes(protocol))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ORIG_BYTES"),Bytes.toBytes(src_bytes))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("RESP_BYTES"),Bytes.toBytes(dst_bytes))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("ORIG_PKTS"),Bytes.toBytes(src_pkts))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("RESP_PKTS"),Bytes.toBytes(dst_pkts))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("CONN_STATE"),Bytes.toBytes(connection_state.toString))
            .addColumn(Bytes.toBytes("PM"),Bytes.toBytes("SOURCE_FILE"),Bytes.toBytes(source_row_key))
        
        val buffer: ListBuffer[Float] = new ListBuffer[Float]()
        split_session.forEachValue(0,skiplist => {
            val iter: util.Iterator[TcpPacketRecord] = skiplist.iterator()
            while(iter.hasNext) {
                val packet: TcpPacketRecord = iter.next
                put.addColumn(Bytes.toBytes("PLD"),Bytes.toBytes(packet.row_key),SerializationUtils.serialize(packet.get_pcap4j_packet))
                buffer += packet.bytes
            }
        })
        
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
