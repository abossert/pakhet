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

object ImpersonationLevel {
    val impersonationLevel: Map[String,String] = Map[String,String](
        "%%1832" -> "Identification",
        "%%1833" -> "Impersonation",
        "%%1840" -> "Delegation",
        "%%1841" -> "Denied by Process Trust Label ACE",
        "%%1842" -> "Yes",
        "%%1843" -> "No",
        "%%1844" -> "System",    
        "%%1845" -> "Not Available",
        "%%1846" -> "Default",
        "%%1847" -> "DisallowMmConfig",
        "%%1848" -> "Off",
        "%%1849" -> "Auto"
    )
}
