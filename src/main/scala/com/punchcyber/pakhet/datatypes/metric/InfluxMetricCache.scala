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

import java.util
import java.util.concurrent._

import org.apache.commons.lang3.SerializationUtils
import org.apache.kafka.clients.producer.ProducerRecord

@SerialVersionUID(101010L)
class InfluxMetricCache(q: ArrayBlockingQueue[ProducerRecord[String,Array[Byte]]],
                        interval: Long = 5L,
                        intervalUnit: TimeUnit = TimeUnit.SECONDS) extends Serializable {
    val cache: ConcurrentHashMap[String,InfluxMetric] = new ConcurrentHashMap[String,InfluxMetric]()
    
    private val ses: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    
    ses.scheduleAtFixedRate(() => {
        val iter: util.Iterator[util.Map.Entry[String,InfluxMetric]] = cache.entrySet().iterator()
        while(iter.hasNext) {
            val entry: util.Map.Entry[String,InfluxMetric] = iter.next()
            val key: String = entry.getKey
            val metric: InfluxMetric = entry.getValue
            
            if(metric.is_done) {
                val kafkaRecord: ProducerRecord[String,Array[Byte]] = new ProducerRecord[String,Array[Byte]]("metrics",key,SerializationUtils.serialize(metric))
                q.put(kafkaRecord)
                iter.remove()
            }
        }
    },interval,interval,intervalUnit)
    
    def put_or_update(metric: InfluxMetric): Unit = {
        val key: String = metric.measurement + metric.timestamp + metric.tags.keySet().toArray.mkString("|")
        synchronized {
            if(cache.containsKey(key)) {
                val current_metric: InfluxMetric = cache.get(key)
                current_metric.add_tag(metric.tags)
                current_metric.add_field(metric.fields)
            }
            else {
                cache.put(key,metric)
            }
        }
    }
    
    def put_or_update(metric_array: Array[InfluxMetric]): Unit = {
        val iter: Iterator[InfluxMetric] = metric_array.toIterator
        while(iter.hasNext) {
            val metric: InfluxMetric = iter.next()
    
            val key: String = metric.measurement + metric.timestamp + metric.tags.keySet().toArray.mkString("|")
            synchronized {
                if(cache.containsKey(key)) {
                    val current_metric: InfluxMetric = cache.get(key)
                    current_metric.add_tag(metric.tags)
                    current_metric.add_field(metric.fields)
                }
                else {
                    cache.put(key,metric)
                }
            }
        }
    }
}
