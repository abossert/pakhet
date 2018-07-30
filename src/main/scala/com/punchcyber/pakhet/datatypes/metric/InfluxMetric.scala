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

package com.punchcyber.pakhet.datatypes.metric

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util
import java.util.UUID.randomUUID

@SerialVersionUID(101010L)
trait InfluxPoint extends Serializable {
    // TODO: Rethink the UID.  Do we really need it?
    val uid:                  String                 = randomUUID().toString
    var last_written: Instant                = Instant.now()
    val tags:                 util.HashMap[String,String] = new util.HashMap[String,String]()
    val fields:               util.HashMap[String,AnyRef]    = new util.HashMap[String,AnyRef]()
    
    val timestamp:         Instant
    val truncate_to:       ChronoUnit
    val timeout:           Long
    val timeoutUnit:       ChronoUnit
    val database:          String
    val retention_policy:  String
    val measurement:       String
    var mtype: String = _
    def is_done: Boolean = {
        if(last_written.until(Instant.now(), timeoutUnit) > timeout) true
        else false
    }
    
    def setLastWritten(): Unit = {
        // TODO: Perhaps being synchronized here is overkill.  It is not a big deal if we declare ourselves done one iteration later than possible.  If performance suffers, kill this
        synchronized {
            last_written = Instant.now()
        }
    }
    
    def add_tag(key: String,value: String): Unit = {
        tags.put(key,value)
        last_written = Instant.now()
    }
    
    def add_tag(tag_map: util.HashMap[String,String]): Unit = {
        tags.putAll(tag_map)
        last_written = Instant.now()
    }
    
    def add_field(key: String, value: AnyRef): Unit = {
        value match {
            case _: java.lang.String =>
                synchronized {
                    if(fields.containsKey(key)) fields.replace(key,value)
                    else fields.put(key,value)
                }
                
            case _: java.lang.Double =>
                synchronized {
                    if(fields.containsKey(key)) {
                        val current: java.lang.Double = fields.get(key).asInstanceOf[java.lang.Double]
                        val new_value: java.lang.Double = current + value.asInstanceOf[java.lang.Double]
                        fields.replace(key,new_value)
                    }
                    else fields.put(key,value)
                }
                
            case _ =>
                // TODO: Need to see if this is the best exception to throw
                throw new IllegalArgumentException
        }
        last_written = Instant.now()
    }
    
    def add_field(field_map: util.HashMap[String,AnyRef]): Unit = {
        val iter: util.Iterator[util.Map.Entry[String,AnyRef]] = field_map.entrySet().iterator()
        while(iter.hasNext) {
            val entry:util.Map.Entry[String,AnyRef] = iter.next()
            val key: String = entry.getKey
            val value: AnyRef = entry.getValue
    
            value match {
                case _: java.lang.String =>
                    synchronized {
                        if(fields.containsKey(key)) fields.replace(key,value)
                        else fields.put(key,value)
                    }
        
                case _: java.lang.Double =>
                    synchronized {
                        if(fields.containsKey(key)) {
                            val current: java.lang.Double = fields.get(key).asInstanceOf[java.lang.Double]
                            val new_value: java.lang.Double = current + value.asInstanceOf[java.lang.Double]
                            fields.replace(key,new_value)
                        }
                        else fields.put(key,value)
                    }
        
                case _ =>
                    // TODO: Need to see if this is the best exception to throw
                    throw new IllegalArgumentException
            }
        }
        last_written = Instant.now()
    }
}

class InfluxMetric(_database: String,
                   _retention_policy: String,
                   _measurement: String,
                   _timestamp: Instant,
                   _truncate_to: ChronoUnit = ChronoUnit.SECONDS,
                   _timeout: Long =  30L,
                   _timeoutUnit: ChronoUnit = ChronoUnit.SECONDS) extends InfluxPoint {
    
    override val database:         String     = _database
    override val retention_policy: String     = _retention_policy
    override val measurement:      String     = _measurement
    override val truncate_to:      ChronoUnit = _truncate_to
    override val timestamp:        Instant    = _timestamp.truncatedTo(truncate_to)
    override val timeout:          Long       = _timeout
    override val timeoutUnit:      ChronoUnit = _timeoutUnit
}