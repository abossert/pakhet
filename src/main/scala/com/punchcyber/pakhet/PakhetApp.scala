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

package com.punchcyber.pakhet

import com.datatorrent.api.annotation.ApplicationAnnotation
import com.datatorrent.api.{DAG, StreamingApplication}
import org.apache.hadoop.conf.Configuration

@ApplicationAnnotation(name = "Pakhet")
class PakhetApp extends StreamingApplication {
    
    override def populateDAG(dag: DAG, configuration: Configuration): Unit = {
    
    }
}
