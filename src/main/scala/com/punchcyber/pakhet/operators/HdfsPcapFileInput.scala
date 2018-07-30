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

package com.punchcyber.pakhet.operators

import java.io._

import com.datatorrent.api.{Context, DefaultOutputPort}
import com.datatorrent.lib.io.fs.AbstractFileInputOperator
import com.punchcyber.pakhet.datatypes.SupportedFileType
import com.punchcyber.pakhet.datatypes.metric.InfluxMetric
import com.punchcyber.pakhet.datatypes.netcom.NetcomComputerName
import com.punchcyber.pakhet.datatypes.packet.AbstractPacketRecord
import com.punchcyber.pakhet.utils.FileMagic.{comp, magics, recursiveFindFileType}
import org.apache.commons.compress.archivers.{ArchiveEntry, ArchiveInputStream, ArchiveStreamFactory}
import org.apache.commons.compress.compressors.CompressorStreamFactory
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.fs.{FSDataInputStream, FileSystem, Path}
import org.pcap4j.core.{NotOpenException, PcapInputStreamHandle, PcapNativeException, PcapPacket}
import org.pcap4j.core.PcapHandle.TimestampPrecision
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.namednumber.DataLinkType
import org.slf4j.{Logger, LoggerFactory}

import scala.collection.mutable
import scala.util.control.Breaks.{break, breakable}
import scala.util.matching.Regex

class HdfsPcapFileInput extends AbstractFileInputOperator[mutable.HashSet[AbstractPacketRecord]] {
    @transient
    private val logger: Logger = LoggerFactory.getLogger(classOf[HdfsPcapFileInput])
    
    @transient
    val metrics: DefaultOutputPort[InfluxMetric] = new DefaultOutputPort[InfluxMetric]()
    @transient
    val output: DefaultOutputPort[AbstractPacketRecord] = new DefaultOutputPort[AbstractPacketRecord]()
    
    /*
     * Values we expect to not be configurable or externally accessible
     */
    private val hadoop_conf: Configuration = new Configuration()
    private val hdfs: FileSystem = FileSystem.get(hadoop_conf)
    
    /**
      * Values we expect to be set in the configuration file:
      *    - core_conf_file         : e.g. /path/to/core-site.xml
      *    - hdfs_conf_file         : e.g. /path/to/hdfs-site.xml
      *    - directoryString        : e.g. /path/to/files|reference
      *    - scanIntervalMillis     : e.g. 60000
      */
    private var core_conf_file: File = _
    def getCore_conf_file: File = core_conf_file
    def setCore_conf_file(core_conf_file: String): Unit = {
        try {
            this.core_conf_file = new File(core_conf_file)
        } catch {
            // TODO: Maybe handle errors more specifically?
            case e: Throwable =>
                logger.error(e.getStackTrace.mkString("\n"))
                throw e
        }
    }
    
    private var hdfs_conf_file: File = _
    def getHdfs_conf_file: File = hdfs_conf_file
    def setHdfs_conf_file(hdfs_conf_file: String): Unit = {
        try {
            this.hdfs_conf_file = new File(hdfs_conf_file)
        } catch {
            // TODO: Maybe handle errors more specifically?
            case e: Throwable =>
                logger.error(e.getStackTrace.mkString("\n"))
                throw e
        }
    }
    
    private var directoryString: String = _
    def getDirectoryString: String = directoryString
    def setDirectoryString(directoryString: String): Unit = this.directoryString = directoryString
    
    /**
      * These are variables that we intend to calculate internally and must not be set directly
      */
    @transient
    var reference: String = _
    def getReference: String = reference
    def setReference(s: String): Unit = reference = s
    
    @transient
    private var fp: Path = _
    
    @transient
    private var filePathStr: String = _
    
    /**
      * These are internal variables that will be set as files are processed
      */
    @transient
    private var nccm: NetcomComputerName = _
    
    @transient
    private var stop: Boolean = _
    
    @transient
    private var pauseTime: Int = _
    
    override def setup(context: Context.OperatorContext): Unit = {
        super.setup(context)
        
        // Setting up our hadoop configuration, throw fatal error if the config files are not found
        for(file <- Array(hdfs_conf_file,core_conf_file)) {
            if(!file.exists() || !file.canRead) {
                throw new FileNotFoundException()
            }
            else {
                hadoop_conf.addResource(file.getAbsolutePath)
            }
        }
        
        pauseTime = context.getValue(Context.OperatorContext.SPIN_MILLIS)
        
        if(filePathStr != null) {
            fp = new Path(filePathStr)
        }
        
        // Parse the directory string (which must be comma-delimited) and the reference mapping
        try {
            val tempSplit: Array[String] = directoryString.split('|')
            directory = tempSplit.head
            reference = tempSplit(1)
        } catch {
            // TODO: need to do some better input validation on the directories
            case e: Throwable =>
                logger.error(e.getStackTrace.mkString("\n"))
                throw e
        }
    }
    
    override protected def openFile(path: Path): InputStream = {
        logger.debug("openFile: curPath = " + path.toString)
        
        fp = path
        filePathStr = fp.toString
        nccm = new NetcomComputerName(fp.getName,1)
        val is: InputStream = super.openFile(fp)
        recursivePcapFileProcessor(is,filePathStr)
        
        is
    }
    
    override protected def closeFile(is: InputStream): Unit = {
        logger.debug("closeFile: fp = " + fp)
        super.closeFile(is)
        
        fp = null
        filePathStr = null
        nccm = null
        stop = true
    }
    
    override def readEntity(): Unit = {}
    
    override def emit(t: mutable.HashSet[AbstractPacketRecord]): Unit = {}
    
    def recursivePcapFileProcessor(is: InputStream,originalFilename: String): Unit = {
        val bis: BufferedInputStream = new BufferedInputStream(is)
        val fileBytes: Array[Byte] = new Array[Byte](512)
        bis.mark(1024)
        bis.read(fileBytes)
        bis.reset()
        
        var fileType: Option[SupportedFileType] = None
        
        breakable {
            for((magicBytes,name) <- magics) {
                if(comp(magicBytes,fileBytes)) {
                    fileType = Some(name)
                    break()
                }
            }
        }
        
        fileType match {
            case Some(ft) =>
                ft match {
                    case SupportedFileType.PCAP =>
                        val fileSize: Long = new File(originalFilename).length()
                        val fileRowKey: String = originalFilename + "|" + fileSize
                        val sensor: String = {
                            val sensorRegex: Regex = """([a-z]{2}-[0-9]{2})-\d{6}""".r
                            sensorRegex.findFirstMatchIn(originalFilename) match {
                                case Some(m) => m.group(1)
                                case None => reference
                            }
                        }
                        
                        var total: Int = 0
                        var good: Int = 0
                        var bad: Int = 0
                        
                        val pcapHandle: PcapInputStreamHandle = new PcapInputStreamHandle
                        pcapHandle.openStream(is)
                        var done: Boolean = false
                        
                        val dlt: DataLinkType = pcapHandle.getDlt
                        val precision: TimestampPrecision = pcapHandle.getTimestampPrecision
                        
                        while(!done) {
                            try {
                                val packet: PcapPacket = pcapHandle.get_next_packet
                                total += 1
                                
                                if (packet != null && packet.contains(classOf[IpV4Packet])) {
                                    good += 1
                                    val packetRecord: AbstractPacketRecord = {
                                        if (sensor.equals("")) AbstractPacketRecord.apply(precision, dlt, fileRowKey, packet, reference)
                                        else AbstractPacketRecord(precision, dlt, fileRowKey, packet, reference, sensor)
                                    }
                                    
                                    output.emit(packetRecord)
                                }
                            } catch {
                                case _:EOFException =>
                                    done = true
                                    pcapHandle.close()
                                
                                case _:NotOpenException =>
                                    done = true
                                    pcapHandle.close()
                                
                                case e:PcapNativeException =>
                                    total += 1
                                    bad += 1
                                    logger.error(e.getStackTrace.mkString("\n"))
                                
                                case e:java.util.concurrent.TimeoutException =>
                                    pcapHandle.close()
                                    logger.error(e.getStackTrace.mkString("\n"))
                            }
                        }

                    case compression if Array(SupportedFileType.GZIP,SupportedFileType.BZIP2).contains(compression) =>
                        recursivePcapFileProcessor(new CompressorStreamFactory().createCompressorInputStream(bis),originalFilename)

                    case archive if Array(SupportedFileType.TAR,SupportedFileType.ZIP).contains(archive) =>
                        val ais: ArchiveInputStream =  new ArchiveStreamFactory().createArchiveInputStream(bis)
                        var entry: ArchiveEntry = ais.getNextEntry
                        
                        while(entry != null) {
                            recursivePcapFileProcessor(ais,originalFilename)
                            
                            try {
                                entry = ais.getNextEntry
                            } catch {
                                case _: Throwable =>
                                    entry = null
                            }
                        }
                }
            case None =>
                throw new UnsupportedEncodingException
        }
    }
    
    override def getScanner: AbstractFileInputOperator.DirectoryScanner = {
        new PcapDirectoryScanner
    }
    
    class PcapDirectoryScanner extends AbstractFileInputOperator.DirectoryScanner {
        override def acceptFile(filePathStr: String): Boolean = {
            val is: FSDataInputStream = hdfs.open(new Path(filePathStr))
            val found: Option[Boolean] = recursiveFindFileType(SupportedFileType.PCAP,is)
            
            found match {
                case Some(bool) =>
                    bool
                
                case None =>
                    false
            }
        }
    }
}
