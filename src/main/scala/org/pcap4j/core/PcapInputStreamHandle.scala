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

package org.pcap4j.core

import java.io.{EOFException, InputStream}
import java.nio.{ByteBuffer, ByteOrder}
import java.time.Instant

import org.pcap4j.core.PcapHandle.TimestampPrecision
import org.pcap4j.packet.namednumber.DataLinkType

class PcapInputStreamHandle extends AutoCloseable {
    private var endianness: ByteOrder = _
    private val little_magic_number: Int = 0xD4C3B2A1
    private val big_magic_number: Int = 0xA1B2C3D4
    private var inputStream: InputStream = _
    
    /* Pcap file header fields (first 4 bytes are magic number)
     * 2 bytes
     */
    private var major_version: Int = _
    // 2 bytes
    private var minor_version: Int = _
    // 4 bytes
    private var timezone_offset: Int = _
    // 4 bytes
    private var timestamp_precision: TimestampPrecision = _
    // 4 bytes
    private var snapshot_length: Int = _
    // 4 bytes
    private var dlt: DataLinkType = _
    
    def getMajorVersion: Int = major_version
    def getMinorVersion: Int = minor_version
    def getTimezoneOffset: Int = timezone_offset
    def getTimestampPrecision: TimestampPrecision = timestamp_precision
    def getSnapshot: Int = snapshot_length
    def getDlt: DataLinkType = dlt
    
    @throws[PcapNativeException]
    def openStream(in: InputStream): Unit = {
        val header: Array[Byte] = new Array[Byte](24)
        inputStream = in
        inputStream.read(header,0,24)
        
        if     (ByteBuffer.wrap(header,0,4).getInt.equals(little_magic_number)) endianness = ByteOrder.LITTLE_ENDIAN
        else if(ByteBuffer.wrap(header,0,4).getInt.equals(big_magic_number))    endianness = ByteOrder.BIG_ENDIAN
        else   throw new PcapNativeException()
        
        major_version       = ByteBuffer.wrap(header,4,2).order(endianness).getShort.toInt
        minor_version       = ByteBuffer.wrap(header,6,2).order(endianness).getShort.toInt
        timezone_offset     = ByteBuffer.wrap(header,8,4).order(endianness).getInt
        timestamp_precision = ByteBuffer.wrap(header,12,4).order(endianness).getInt match {
            case 0 => TimestampPrecision.MICRO
            case 1 => TimestampPrecision.NANO
            case _ => throw new PcapNativeException()
        }
        snapshot_length = ByteBuffer.wrap(header,16,4).order(endianness).getInt
        dlt = ByteBuffer.wrap(header,20,4).order(endianness).getInt match {
            case 0   => DataLinkType.NULL
            case 1   => DataLinkType.EN10MB
            case 6   => DataLinkType.IEEE802
            case 9   => DataLinkType.PPP
            case 10  => DataLinkType.FDDI
            case 12  => DataLinkType.RAW
            case 14  => DataLinkType.RAW
            case 50  => DataLinkType.PPP_SERIAL
            case 105 => DataLinkType.IEEE802_11
            case 113 => DataLinkType.LINUX_SLL
            case 127 => DataLinkType.IEEE802_11_RADIO
            case 143 => DataLinkType.DOCSIS
            case _   => throw new PcapNativeException()
        }
    }
    
    @throws[EOFException]
    def get_next_packet: PcapPacket = {
        val buff: Array[Byte] = new Array[Byte](16)
        
        inputStream.read(buff) match {
            case -1 => throw new EOFException()
            case _ =>
                val ts_sec: Long =  ByteBuffer.wrap(buff,0,4).order(endianness).getInt.toLong
                val ts_usec: Long = ByteBuffer.wrap(buff,4,4).order(endianness).getInt.toLong
                val incl_len: Int = ByteBuffer.wrap(buff,8,4).order(endianness).getInt
                val orig_len: Int = ByteBuffer.wrap(buff,12,4).order(endianness).getInt
                
                val ts: Instant = {
                    if(timestamp_precision.equals(TimestampPrecision.MICRO)) Instant.ofEpochSecond(ts_sec,ts_usec * 1000)
                    else Instant.ofEpochSecond(ts_sec,ts_usec)
                }
                
                val packet: Array[Byte] = new Array[Byte](incl_len)
                inputStream.read(packet)
                
                new PcapPacket(packet,dlt,ts,orig_len)
        }
    }
    
    override def close(): Unit = {
        inputStream.close()
    }
}
