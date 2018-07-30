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

package com.punchcyber.pakhet.datatypes.evtx

import java.nio.ByteBuffer
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util
import java.util.UUID

import com.esotericsoftware.kryo.serializers.FieldSerializer.Bind
import com.esotericsoftware.kryo.serializers.JavaSerializer
import com.punchcyber.pakhet.datatypes.Pudable
import com.punchcyber.pakhet.datatypes.evtx.ImpersonationLevel.impersonationLevel
import com.punchcyber.pakhet.datatypes.evtx.MsEventId.event_id_mapping
import com.punchcyber.pakhet.datatypes.metric.InfluxMetric
import com.punchcyber.pakhet.datatypes.netcom.NetcomComputerName
import org.apache.hadoop.hbase.client.Put
import org.apache.hadoop.hbase.util.Bytes

import scala.collection.mutable


@SerialVersionUID(101010L)
class EvtxEvent extends Pudable with Serializable {
    val uuid: String = UUID.randomUUID().toString
    var Provider_Name: String = ""
    var Provider_Guid: String = ""
    var eventID: Int = 0
    var eventID_description: String = ""
    var qualifiers: String = ""
    var version: Int = 0
    var level: Int = 0
    var task: Int = 0
    var opcode: Int = 0
    var keywords: String = ""
    
    @Bind(classOf[JavaSerializer])
    var systemTime: Instant = Instant.now()
    var eventRecordID: Long = 0L
    var ProcessID: Int = 0
    var threadID: Int = 0
    var Channel: String = ""
    var computer: String = ""
    var correlationActivityID: String = ""
    var correlationRelatedActivityID: String = ""
    var securityUserID: String = ""
    // TODO: don't hardcode this
    var reference: String = ""
    var sensor: String = ""
    
    // For now, this is generic
    val eventData: mutable.LinkedHashMap[String,(String,String)] = mutable.LinkedHashMap[String,(String,String)]()
    
    def this(fields: mutable.LinkedHashMap[String,(String,String)]) = {
        this
        init(fields)
    }
    
    override def toString: String = {
        var string: String =
            f"""Event Record # : $eventRecordID
               |Timestamp      : ${systemTime.toString}
               |Computer       : $computer
               |    Version    : $version
               |    Level      : $level
               |    Task       : $task
               |    Channel    : $Channel
               |Provider GUID  : $Provider_Guid
               |Provider Name  : $Provider_Name
               |
               |Event ID       : $eventID
               |    description: $eventID_description
               |    Qualifiers : $qualifiers
               |    Op Code    : $opcode
               |    Keywords   : $keywords
               |    Process ID : $ProcessID
               |    Thread ID  : $threadID
               |
               |Correlation    :
               |    Activity ID: $correlationActivityID
               |    Related  ID: $correlationRelatedActivityID
               |
               |Security       :
               |    User ID    : $securityUserID
               |
               |Event Data     :

""".stripMargin
        
        val iter: Iterator[(String,(String,Any))] = eventData.toIterator
        while(iter.hasNext) {
            val (key,(value,tipe)) = iter.next()
            if(key.endsWith("IMPERSONATIONLEVEL") && impersonationLevel.contains(value)) {
                string += f"$key : ${impersonationLevel(value)} -- $tipe\n".stripMargin
            }
            else {
                string += f"$key : $value -- $tipe\n".stripMargin
            }
        }
        string
    }
    
    def init(fields: mutable.LinkedHashMap[String,(String,String)]): Unit = {
        Provider_Name = try { fields("SYSTEM_PROVIDER_NAME")._1.toString } catch { case _: NoSuchElementException => "" }
        Provider_Guid = try { fields("SYSTEM_PROVIDER_GUID")._1.toString } catch { case _: NoSuchElementException => "" }
        eventID = try { fields("SYSTEM_EVENTID")._1.toInt } catch { case _: NoSuchElementException => 0 }
        eventID_description = try { event_id_mapping(fields("SYSTEM_EVENTID")._1.toInt) } catch { case _: NoSuchElementException => "" }
        qualifiers = try { fields("SYSTEM_EVENTID_QUALIFIERS")._1.toString } catch { case _: NoSuchElementException => "" }
        version = try { fields("SYSTEM_VERSION")._1.toInt } catch { case _: NoSuchElementException => 0 }
        level = try { fields("SYSTEM_LEVEL")._1.toInt } catch { case _: NoSuchElementException => 0 }
        task = try { fields("SYSTEM_TASK")._1.toInt } catch { case _: NoSuchElementException => 0 }
        opcode = try { fields("SYSTEM_OPCODE")._1.toInt } catch { case _: NoSuchElementException => 0 }
        keywords = try { fields("SYSTEM_KEYWORDS")._1.toString } catch { case _: NoSuchElementException => "" }
        systemTime = try { Instant.parse(fields("SYSTEM_TIMECREATED_SYSTEMTIME")._1.replace(" ","T") + "Z") } catch { case _: NoSuchElementException => Instant.now() }
        eventRecordID = try { fields("SYSTEM_EVENTRECORDID")._1.toLong } catch { case _: NoSuchElementException => 0L }
        ProcessID = try { fields("SYSTEM_EXECUTION_PROCESSID")._1.toInt } catch { case _: NoSuchElementException => 0 }
        threadID = try { fields("SYSTEM_EXECUTION_THREADID")._1.toInt } catch { case _: NoSuchElementException => 0 }
        Channel = try { fields("SYSTEM_CHANNEL")._1.toString } catch { case _: NoSuchElementException => "" }
        computer = try { fields("SYSTEM_COMPUTER")._1.toString } catch { case _: NoSuchElementException => "" }
        correlationActivityID = try { fields("SYSTEM_CORRELATION_ACTIVITYID")._1.toString } catch { case _: NoSuchElementException => "" }
        correlationRelatedActivityID = try { fields("SYSTEM_CORRELATION_RELATEDACTIVITYID")._1.toString } catch { case _: NoSuchElementException => "" }
        securityUserID = try { fields("SYSTEM_SECURITY_USERID")._1.toString } catch { case _: NoSuchElementException => "" }
        
        try {
            fields.remove("SYSTEM_PROVIDER_NAME")
            fields.remove("SYSTEM_PROVIDER_GUID")
            fields.remove("SYSTEM_EVENTID")
            fields.remove("SYSTEM_EVENTID_QUALIFIERS")
            fields.remove("SYSTEM_VERSION")
            fields.remove("SYSTEM_LEVEL")
            fields.remove("SYSTEM_TASK")
            fields.remove("SYSTEM_OPCODE")
            fields.remove("SYSTEM_KEYWORDS")
            fields.remove("SYSTEM_TIMECREATED_SYSTEMTIME")
            fields.remove("SYSTEM_EVENTRECORDID")
            fields.remove("SYSTEM_EXECUTION_PROCESSID")
            fields.remove("SYSTEM_EXECUTION_THREADID")
            fields.remove("SYSTEM_CHANNEL")
            fields.remove("SYSTEM_COMPUTER")
            fields.remove("SYSTEM_CORRELATION_ACTIVITYID")
            fields.remove("SYSTEM_CORRELATION_RELATEDACTIVITYID")
            fields.remove("SYSTEM_SECURITY_USERID")
        } catch {
            case _: NullPointerException =>
        }
        
        eventData ++= fields
    
        if(eventData.contains("EVENTDATA_DATA_TARGETUSERNAME")) {
            try {
                val cn: NetcomComputerName = new NetcomComputerName(eventData("EVENTDATA_DATA_TARGETUSERNAME")._1,1)
                eventData.put("EVENTDATA_DATA_TARGETUSERNAME_SITE_CODE",(cn.site_code,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_TARGETUSERNAME_FUNCTIONAL_CODE",(cn.functional_code,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_TARGETUSERNAME_FUNCTIONAL_CODE_DESCRIPTION",(cn.functional_code_description,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_TARGETUSERNAME_CUSTOM_ID",(cn.custom_identifier,"WStringTypeNode"))
            } catch {
                case _: IllegalArgumentException =>
            }
        }
        else if(eventData.contains("EVENTDATA_DATA_SUBJECTUSERNAME")) {
            try {
                val cn: NetcomComputerName = new NetcomComputerName(eventData("EVENTDATA_DATA_SUBJECTUSERNAME")._1,1)
                eventData.put("EVENTDATA_DATA_SUBJECTUSERNAME_SITE_CODE",(cn.site_code,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_SUBJECTUSERNAME_FUNCTIONAL_CODE",(cn.functional_code,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_SUBJECTUSERNAME_FUNCTIONAL_CODE_DESCRIPTION",(cn.functional_code_description,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_SUBJECTUSERNAME_CUSTOM_ID",(cn.custom_identifier,"WStringTypeNode"))
            } catch {
                case _: IllegalArgumentException =>
            }
        }
        else if(eventData.contains("EVENTDATA_DATA_WORKSTATION")) {
            try {
                val cn: NetcomComputerName = new NetcomComputerName(eventData("EVENTDATA_DATA_WORKSTATION")._1,1)
                eventData.put("EVENTDATA_DATA_TARGETUSERNAME_SITE_CODE",(cn.site_code,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_TARGETUSERNAME_FUNCTIONAL_CODE",(cn.functional_code,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_TARGETUSERNAME_FUNCTIONAL_CODE_DESCRIPTION",(cn.functional_code_description,"WStringTypeNode"))
                eventData.put("EVENTDATA_DATA_TARGETUSERNAME_CUSTOM_ID",(cn.custom_identifier,"WStringTypeNode"))
            } catch {
                case _: IllegalArgumentException =>
            }
        }
        else if(eventData.contains("EVENTDATA_DATA_LOGONTYPE")) {
            val (trans,t) = eventData("EVENTDATA_DATA_LOGONTYPE")
    
            trans match {
                case "2"  => eventData.update("EVENTDATA_DATA_LOGONTYPE",("Interactive",t))
                case "3"  => eventData.update("EVENTDATA_DATA_LOGONTYPE",("Network",t))
                case "4"  => eventData.update("EVENTDATA_DATA_LOGONTYPE",("Batch",t))
                case "5"  => eventData.update("EVENTDATA_DATA_LOGONTYPE",("Service",t))
                case "7"  => eventData.update("EVENTDATA_DATA_LOGONTYPE",("Unlock",t))
                case "8"  => eventData.update("EVENTDATA_DATA_LOGONTYPE",("NetworkCleartext",t))
                case "9"  => eventData.update("EVENTDATA_DATA_LOGONTYPE",("NewCredentials",t))
                case "10" => eventData.update("EVENTDATA_DATA_LOGONTYPE",("RemoteInteractive",t))
                case "11" => eventData.update("EVENTDATA_DATA_LOGONTYPE",("CachedInteractive",t))
                case _ =>
            }
        }
    }
    
    def getInfluxMetric: Array[InfluxMetric] = {
        val metric: InfluxMetric = new InfluxMetric(
            "IpMetrics",
            "indefinite",
            "evtx_event_id",
            systemTime,
            ChronoUnit.MINUTES,
            70L,
            ChronoUnit.SECONDS)
        
        val tagMap: util.HashMap[String,String] = new util.HashMap[String,String]()
        tagMap.put("reference",reference)
        tagMap.put("sensor",sensor)
        tagMap.put("event_id",eventID.toString)
        
        metric.add_tag(tagMap)
    
        metric.add_field("count",1D:java.lang.Double)
        metric.mtype = "EVTX"
        
        Array(metric)
    }
    
    override def getHBaseTableName: String = {
        f"default:$reference-evtx"
    }
    
    override def getHBasePut: Put = {
        val ts: ByteBuffer = ByteBuffer.allocate(12)
        ts.putLong(0,systemTime.toEpochMilli)
        ts.putInt(8,systemTime.getNano)
        
        val cf: Array[Byte] = Bytes.toBytes("ED")
        val put: Put = new Put(Bytes.toBytes(Array(eventID.toString,computer,eventRecordID,uuid).mkString("|")),systemTime.toEpochMilli)
        put.addColumn(cf,Bytes.toBytes("SYSTEM_PROVIDER_NAME"),Bytes.toBytes(Provider_Name))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_PROVIDER_GUID"),Bytes.toBytes(Provider_Guid))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_EVENTID"),Bytes.toBytes(eventID))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_EVENTID_DESCRIPTION"),Bytes.toBytes(eventID_description))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_EVENTID_QUALIFIERS"),Bytes.toBytes(qualifiers))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_VERSION"),Bytes.toBytes(version))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_LEVEL"),Bytes.toBytes(level))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_TASK"),Bytes.toBytes(task))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_OPCODE"),Bytes.toBytes(opcode))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_KEYWORDS"),Bytes.toBytes(keywords))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_SYSTEMTIME"),ts.array())
        put.addColumn(cf,Bytes.toBytes("SYSTEM_EVENTRECORDID"),Bytes.toBytes(eventRecordID))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_PROCESSID"),Bytes.toBytes(ProcessID))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_THREADID"),Bytes.toBytes(threadID))
        if(Channel != "") put.addColumn(cf,Bytes.toBytes("SYSTEM_CHANNEL"),Bytes.toBytes(Channel))
        if(computer != "") put.addColumn(cf,Bytes.toBytes("SYSTEM_COMPUTER"),Bytes.toBytes(computer))
        if(correlationActivityID != "") put.addColumn(cf,Bytes.toBytes("SYSTEM_CORRELATION_ACTIVITYID"),Bytes.toBytes(correlationActivityID))
        if(correlationRelatedActivityID != "") put.addColumn(cf,Bytes.toBytes("SYSTEM_CORRELATION_RELATEDACTIVITYID"),Bytes.toBytes(correlationRelatedActivityID))
        if(securityUserID != "") put.addColumn(cf,Bytes.toBytes("SYSTEM_SECURITY_USERID"),Bytes.toBytes(securityUserID))
        
        val nccm: NetcomComputerName = new NetcomComputerName(computer,1)
        put.addColumn(cf,Bytes.toBytes("SYSTEM_SITE_CODE"),Bytes.toBytes(nccm.site_code))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_FUNCTIONAL_CODE"),Bytes.toBytes(nccm.functional_code))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_FUNCTIONAL_CODE_DESCRIPTION"),Bytes.toBytes(nccm.functional_code_description))
        put.addColumn(cf,Bytes.toBytes("SYSTEM_CUSTOM_ID"),Bytes.toBytes(nccm.custom_identifier))
        
        val iter:Iterator[(String,(String,Any))] = eventData.toIterator
        while(iter.hasNext) {
            val (key,(value,tip)) = iter.next()
            val t: String = tip.asInstanceOf[String]
            if(t.equals("SystemtimeTypeNode")) {
                val inst: Instant = Instant.parse(value.replace(" ","T") + "Z")
                val ts: ByteBuffer = ByteBuffer.allocate(12)
                ts.putLong(inst.toEpochMilli)
                ts.putInt(inst.getNano)
                
                put.addColumn(cf,Bytes.toBytes(key),ts.array())
            }
            else if(value.equals("::1")) {
                put.addColumn(cf,Bytes.toBytes(key),Bytes.toBytes("127.0.0.1"))
            }
            else {
                """::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""".r.findFirstMatchIn(value) match {
                    case Some(regex) =>
                        val ip: String = regex.group(1)
                        put.addColumn(cf,Bytes.toBytes(key),Bytes.toBytes(ip))
                    case None =>
                        put.addColumn(cf,Bytes.toBytes(key),Bytes.toBytes(value))
                }
            }
        }
        
        put
    }
}
