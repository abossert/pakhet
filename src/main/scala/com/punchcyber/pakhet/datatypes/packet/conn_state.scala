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
sealed abstract class conn_state(code: String,description: String) extends Serializable {
    override def toString: String = code
    def toDescription: String = description
}

case object S0     extends conn_state("S0"    ,"Connection attempt seen, no reply.")
case object S1     extends conn_state("S1"    ,"Connection established, not terminated.")
case object SF     extends conn_state("SF"    ,"Normal establishment and termination.") // Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there will not be any byte counts in the summary, while for SF there will be.
case object REJ    extends conn_state("REJ"   ,"Connection attempt rejected.")
case object S2     extends conn_state("S2"    ,"Connection established and close attempt by originator seen, but no reply from responder.")
case object S3     extends conn_state("S3"    ,"Connection established and close attempt by responder seen, but no reply from originator.")
case object RSTO   extends conn_state("RSTO"  ,"Connection established, originator aborted; sent a RST.")
case object RSTR   extends conn_state("RSTR"  ,"Responder sent a RST.")
case object RSTOS0 extends conn_state("RSTOS0","Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.")
case object RSTRH  extends conn_state("RSTRH" ,"RST, we never saw a SYN from the purported originator.") // "Responder sent a SYN ACK followed by a " Bro seems to treat this without the requirement for a preceding syn-ack
case object SH     extends conn_state("SH"    ,"Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder.") // hence the connection was “half” open
case object SHR    extends conn_state("SHR"   ,"FIN, we never saw a SYN from the originator.") // "Responder sent a SYN ACK followed by a " Bro seems to treat this without the requirement for a preceding syn-ack
case object OTH    extends conn_state("OTH"   ,"No SYN seen, just midstream traffic (a “partial connection” that was not later closed).")
case object NOTSET extends conn_state("NOTSET","DO not use this.  This value is for developer use to catch edge cases")
