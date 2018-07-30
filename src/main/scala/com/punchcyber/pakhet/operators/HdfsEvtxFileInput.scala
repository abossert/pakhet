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

import java.util.concurrent.ConcurrentLinkedQueue

import com.datatorrent.api.{Context, DefaultOutputPort}
import com.datatorrent.lib.io.fs.AbstractFileInputOperator
import com.punchcyber.pakhet.datatypes.SupportedFileType
import com.punchcyber.pakhet.datatypes.evtx.{EvtxEvent, EvtxNodeVisitor}
import com.punchcyber.pakhet.datatypes.metric.InfluxMetric
import com.punchcyber.pakhet.datatypes.netcom.NetcomComputerName
import com.punchcyber.pakhet.utils.FileMagic.{comp, magics, recursiveFindFileType}
import org.apache.commons.compress.archivers.{ArchiveEntry, ArchiveInputStream, ArchiveStreamFactory}
import org.apache.commons.compress.compressors.CompressorStreamFactory
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.fs.{FSDataInputStream, FileSystem, Path}
import org.apache.nifi.logging.ComponentLog
import org.apache.nifi.processors.evtx.parser.bxml.RootNode
import org.apache.nifi.processors.evtx.parser.{ChunkHeader, FileHeader, Record}
import org.apache.nifi.util.MockComponentLog
import org.slf4j.{Logger, LoggerFactory}

import scala.collection.mutable
import scala.util.control.Breaks.{break, breakable}

class HdfsEvtxFileInput extends AbstractFileInputOperator[mutable.HashSet[EvtxEvent]] {
    @transient
    private val logger: Logger = LoggerFactory.getLogger(classOf[HdfsEvtxFileInput])
    @transient
    private val mock_logger: MockComponentLog = new MockComponentLog("fakeNews",this)
    
    @transient
    val metrics: DefaultOutputPort[InfluxMetric] = new DefaultOutputPort[InfluxMetric]()
    @transient
    val output: DefaultOutputPort[EvtxEvent] = new DefaultOutputPort[EvtxEvent]()
    
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
    
    override def getScanner: AbstractFileInputOperator.DirectoryScanner = {
        new EvtxDirectoryScanner
    }
    
    /**
     * These are internal variables that will be set as files are processed
     */
    @transient
    private var nccm: NetcomComputerName = _
    
    @transient
    private var stop: Boolean = _
    
    @transient
    private var pauseTime: Int = _
    
    @transient
    private val chunks: ConcurrentLinkedQueue[ChunkHeader] = new ConcurrentLinkedQueue[ChunkHeader]()
    
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
        recursiveEvtxFileProcessor(is)
        
        is
    }
    
    override protected def closeFile(is: InputStream): Unit = {
        logger.debug("closeFile: fp = " + fp)
        super.closeFile(is)
        
        fp = null
        filePathStr = null
        chunks.clear()
        nccm = null
        stop = true
    }
    
    override protected def readEntity(): mutable.HashSet[EvtxEvent] = {
        val events: mutable.HashSet[EvtxEvent] = mutable.HashSet[EvtxEvent]()
        
        if(chunks.isEmpty) {
            logger.info("readEntity: EOF for: " + fp.toString)
            null
        }
        else {
            val chunkHeader: ChunkHeader = chunks.poll()
            
            var record: Record = new Record(chunkHeader.getBinaryReader,chunkHeader)
            while(record != null) {
                try {
                    val rootnode: RootNode = record.getRootNode
                    val xmlVisitor: EvtxNodeVisitor = new EvtxNodeVisitor(rootnode, mutable.LinkedHashMap[String, (String, String)]())
                    
                    val evt: EvtxEvent = new EvtxEvent(xmlVisitor.event)
                    evt.reference = reference
                    evt.sensor = nccm.computer_name
                    events += evt
                } catch {
                    case e: IllegalArgumentException => logger.error(f"BAD RECORD: ${record.getRecordNum} \n" + e.getStackTrace.mkString("\n"))
                    case e: IOException => logger.error(f"BAD RECORD: ${record.getRecordNum} \n" + e.getStackTrace.mkString("\n"))
                } finally {
                    try {
                        record = new Record(chunkHeader.getBinaryReader,chunkHeader)
                    } catch {
                        case _: IOException => record = null
                        case _: NullPointerException => record = null
                    }
                }
            }
            
            events
        }
    }
    
    override protected def emit(tuple: mutable.HashSet[EvtxEvent]): Unit = {
        tuple.foreach((t:EvtxEvent) => {
            output.emit(t)
            val ma: Array[InfluxMetric] = t.getInfluxMetric
            for(m <- ma) {
                metrics.emit(m)
            }
            
        })
    }
    
    private def recursiveEvtxFileProcessor(is: InputStream,chunkCount: Int = 0): Int = {
        var cc: Int = chunkCount
        
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
                    case SupportedFileType.EVTX =>
                        val fileHeader: FileHeader = EvtxFileHeaderFactory.create(bis,mock_logger)
                        var chunkHeader: ChunkHeader = fileHeader.next()
                        
                        while(chunkHeader != null) {
                            cc += 1
                            chunks.offer(chunkHeader)
                            
                            try {
                                chunkHeader = fileHeader.next()
                            } catch {
                                case _: IOException => chunkHeader = null
                            }
                        }
                    
                    case compression if Array(SupportedFileType.GZIP,SupportedFileType.BZIP2).contains(compression) =>
                        recursiveEvtxFileProcessor(new CompressorStreamFactory().createCompressorInputStream(bis),cc)
                    
                    case archive if Array(SupportedFileType.TAR,SupportedFileType.ZIP).contains(archive) =>
                        val ais: ArchiveInputStream =  new ArchiveStreamFactory().createArchiveInputStream(bis)
                        var entry: ArchiveEntry = ais.getNextEntry
                        
                        while(entry != null) {
                            recursiveEvtxFileProcessor(ais,cc)
                            
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
        cc
    }
    
    object EvtxFileHeaderFactory {
        def create(inputStream: InputStream, componentLog: ComponentLog): FileHeader = {
            new FileHeader(inputStream,componentLog)
        }
    }
    
    class EvtxDirectoryScanner extends AbstractFileInputOperator.DirectoryScanner {
        override def acceptFile(filePathStr: String): Boolean = {
            val is: FSDataInputStream = hdfs.open(new Path(filePathStr))
            val found: Option[Boolean] = recursiveFindFileType(SupportedFileType.EVTX,is)
            
            found match {
                case Some(bool) =>
                    bool
                
                case None =>
                    false
            }
        }
    }
}
