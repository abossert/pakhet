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

package com.punchcyber.pakhet.utils

import java.lang

object GeneralUtils {
    def sortAndStringify(i1: String,i2: String): String = {
        if(i1 > i2) {
            i2 + i1
        }
        else {
            i1 + i2
        }
    }
    
    def sortAndStringify(i1: Int,i2: Int): String = {
        if(i1 > i2) {
            Array(i2,i1).mkString
        }
        else {
            Array(i1,i2).mkString
        }
    }
    
    def sortAndStringify(i1: lang.Float,i2: lang.Float): String = {
        if(i1 > i2) {
            Array(i2,i1).mkString
        }
        else {
            Array(i1,i2).mkString
        }
    }
}
