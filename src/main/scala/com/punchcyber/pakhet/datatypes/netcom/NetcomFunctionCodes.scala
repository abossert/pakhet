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

object NetcomFunctionCodes {
    val function_code_map: Map[String,String] = Map[String,String](
        "A0" -> "Application server",
        "A1" -> "Domain controller",
        "A2" -> "Certificate Authority Server",
        "A3" -> "Cluster server",
        "A4" -> "Database server",
        "A5" -> "DHCP server",
        "A6" -> "DNS server",
        "A7" -> "File server",
        "A8" -> "Gateway or Bridge server",
        "A9" -> "Global Catalog",
        "B0" -> "AMHS file server",
        "B1" -> "Mail server (MS Exchange 5.5 or earlier)",
        "B2" -> "Media server",
        "B3" -> "Message queue server",
        "B4" -> "Remote Access server",
        "B5" -> "Remote Activity server",
        "B6" -> "Security server",
        "B7" -> "System management server",
        "B8" -> "Transaction server",
        "B9" -> "Terminal server",
        "C0" -> "TBD",
        "C1" -> "WINS server",
        "C2" -> "Web server",
        "C3" -> "Anti Virus server",
        "C4" -> "Blackberry server",
        "C5" -> "List server",
        "C6" -> "HTTP virtual server",
        "C7" -> "SMTP virtual server",
        "C8" -> "MS Exchange virtual server",
        "C9" -> "Responder server",
        "D0" -> "Unified Messaging server",
        "D1" -> "Repeater server",
        "D2" -> "Hercules server",
        "D3" -> "Windows",
        "D4" -> "Windows (read-only)",
        "D5" -> "Windows (core)",
        "D6" -> "OCS Archiving and CDR",
        "D7" -> "OCS Director",
        "D8" -> "OCS Front End",
        "D9" -> "OCS Web Components",
        "F0" -> "OCS AV Conferencing",
        "F1" -> "MS Exchange Mailbox server",
        "F2" -> "MS Exchange Hub Transport server",
        "F3" -> "MS Exchange Client Access server",
        "F4" -> "MS Exchange Edge Transport server",
        "F5" -> "OCS Web Conferencing",
        "F6" -> "OCS Access Edge",
        "F7" -> "OCS A/V Edge",
        "F8" -> "Web Conferencing Edge",
        "F9" -> "OCS Mediation server",
        "H0" -> "OCS Communicator Web Access",
        "H1" -> "OCS QoE server",
        "H2" -> "OCS update server",
        "H3" -> "OCS database server",
        "H4" -> "OCS archive",
        "H5" -> "OCS Consolidated server",
        "H6" -> "OCS Access and Web Conferencing server combined",
        "H7" -> "OCS pool (virtual server)",
        "H8" -> "OCS Director (virtual server)",
        "H9" -> "OCS A/V Edge (virtual server)",
        "K0" -> "OCS Access Edge (virtual server)",
        "K1" -> "Windows cluster (virtual server)",
        "K2" -> "SQL cluster (virtual server)",
        "K3" -> "HBSS-ePO server (App/SQL combined)",
        "K4" -> "HBSS-ePO server (App only)",
        "K5" -> "HBSS-ePO server (SQL only)",
        "K6" -> "HBSS-SuperAgent Distributed Repository (SADR)",
        "K7" -> "HBSS Remote Console",
        "K8" -> "VMware ESX server",
        "K9" -> "Hyper-V",
        "L0" -> "OOBM-Remote Desktop Session Host",
        "L2" -> "OOBM-Remote Desktop Licensing",
        "L4" -> "OOBM-Remote Desktop Web Access",
        "L5" -> "OOBM-Remote Desktop Gateway",
        "L6" -> "OOBM-Remote Desktop  Connection Broker",
        "L7" -> "OOBM -",
        "M0" -> "IdAM - FIM only (Forefront Identity Manager)",
        "M1" -> "FIM and SQL (combined installation)",
        "M2" -> "AD LDS Active Directory Lightweight Directory Services",
        "M3" -> "IdAM - TBD",
        "M4" -> "IdAM - TBD",
        "M5" -> "IdAM - TBD",
        "M6" -> "IdAM - TBD",
        "M7" -> "IdAM - TBD",
        "M8" -> "IdAM - TBD",
        "M9" -> "IdAM - TBD",
        "BE" -> "Back End Mail server (E2K3)",
        "BG" -> "Backup Gateway server",
        "BH" -> "Bridgehead Mail server (E2K3)",
        "DF" -> "Distributed File Server (DFS)",
        "DM" -> "Monitoring Device - Devices with OS connected to the network, not a workstation or notebook (i.e. HVAC monitors)",
        "DS" -> "Digital sender",
        "EM" -> "Enterprise Management Server",
        "FE" -> "Front End Mail (E23K)",
        "FS" -> "Fax server",
        "FX" -> "Network Connected fax machine",
        "MC" -> "Multi-function Copier",
        "NB" -> "Notebook Computer",
        "ND" -> "Notebook Dedicated, not a server",
        "NM" -> "Network Management Server",
        "NX" -> "Notebook device not connected to the network (stand-alone)",
        "PG" -> "DMS Primary Gateway Server",
        "PL" -> "Plotter",
        "PO" -> "Portal Web Server",
        "PR" -> "Printer",
        "PS" -> "Print server",
        "PX" -> "Proxy server",
        "SC" -> "Scanner",
        "TB" -> "Tablet PC",
        "WD" -> "Workstation Dedicated, not a server",
        "WK" -> "Workstation/Desktop",
        "WX" -> "Workstation not connected to the network (stand-alone)"
    )
}
