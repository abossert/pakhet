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

package com.punchcyber.pakhet.datatypes.netcom

import com.punchcyber.pakhet.datatypes.netcom.NetcomFunctionCodes.function_code_map
import scala.util.matching.Regex

/*This mapping info is from
* https://vm00-confluence.gotgdt.net:8443/display/PAV/NETCOM+Computer+Naming+Convention
* and contains FOUO information.  TODO: Need to validate appropriate handling for FOUO in code
*
* Example names:
*
*   SSSS     : Site code
*   FC       : Functional Code
*   CCCCCCCCC: 1-9 character Custom ID (No details provided, but assumed to be zero-padded)
*
*   SSSSFCCCCCCCCC
*   ---------------
*   RADFA1NWVXD0001
*   REDSA1NANER2001
*   RILEA1NWP000001
*   RILEA1NWP000002
*   ROCKA1NWP000001
*   YAKIA1NWP000001
*   DRUMA1NEP000001
* */

@throws[IllegalArgumentException]
@SerialVersionUID(101010L)
class NetcomComputerName(version: Int = 1) extends Serializable {
    val v1_regex: Regex = """([A-Z0-9]{4})([A-Z0-9]{2})([A-Z1-9]{1,9})""".r
    val v2_regex: Regex = """([A-Z0-9]{4})([A-Z0-9]{6})([A-Z0-9]{2})([A-Z1-9]{1,3})""".r
    
    /*private */var naming_version: Int = version
    
    // V1/2
    /*private */var site_code: String = ""
    // V1/2
    /*private */var functional_code: String = ""
    // V1/2
    /*private */var functional_code_description: String = ""
    // V1/2
    /*private */var custom_identifier: String = ""
    // V2 only
    /*private */var uic: String = ""
    
    var computer_name: String = ""
    
    
    
    def this(_computer_name: String, _version: Int) {
        this
        
        naming_version = _version
        
        if(naming_version == 1) {
            v1_regex.findFirstMatchIn(_computer_name.toUpperCase) match {
                case Some(regex) =>
                    val (sc,fc,ci) = (regex.group(1),regex.group(2),regex.group(3))
                    site_code = sc
                    functional_code = fc
                    custom_identifier = ci
                    computer_name = site_code + functional_code + custom_identifier
                    
                    if(function_code_map.contains(functional_code)) functional_code_description = function_code_map(functional_code)
                    else throw new IllegalArgumentException(f"We don't know this functional code: ${_computer_name.toUpperCase} $functional_code")
                
                case None => throw new IllegalArgumentException(f"No REGEX MATCH: ${_computer_name}")
            }
        }
        else if(naming_version == 2) {
            v2_regex.findFirstMatchIn(_computer_name.toUpperCase) match {
                case Some(regex) =>
                    val (sc,u,fc,ci) = (regex.group(1),regex.group(2),regex.group(3),regex.group(4))
                    site_code = sc
                    uic = u
                    functional_code = fc
                    custom_identifier = ci
                    computer_name = site_code + uic + functional_code + custom_identifier
    
                    if(function_code_map.contains(functional_code)) functional_code_description = function_code_map(functional_code)
                    else throw new IllegalArgumentException(f"We don't know this functional code: ${_computer_name.toUpperCase} $functional_code")
        
                case None => throw new IllegalArgumentException(f"No REGEX MATCH: ${_computer_name}")
            }
        }
        else {
            throw new IllegalArgumentException("Got wrong Version, needed 1 or 2")
        }
    }
}
