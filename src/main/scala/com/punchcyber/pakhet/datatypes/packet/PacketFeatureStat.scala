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

@SerialVersionUID(101010L)
class PacketFeatureStat(buffer: Array[Float]) extends Serializable {
    private val x: Array[Float] = buffer.sorted
    val min: Float = x.head
    val mean: Float = x.sum / x.length
    val median: Float = {
        val(l,u) = x.splitAt(x.length / 2)
        if(x.length % 2 == 0) { (l.last + u.head) / 2F }
        else { u.head }
    }
    val max: Float = x.last
    val std_dev: Float = Math.sqrt(x.map(_ - mean).map(t => t * t).sum / x.length).toFloat
}
