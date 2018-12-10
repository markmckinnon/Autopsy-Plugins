# This python autopsy module will process the TeraCopy database from the TeraCopy Application.
# Thanks to Kevin Pagano (@KevinPagano3) for the information
#     https://www.stark4n6.com/2018/11/teracopy-forensic-analysis-part-1.html
#     https://www.stark4n6.com/2018/11/teracopy-forensic-analysis-part-2.html
#     https://www.stark4n6.com/2018/12/teracopy-forensic-analysis-part-3.html
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> gmail [dot] com]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Process_TeraCopy sqlite database.
# December 2018
# 
# Comments 
#   Version 1.0 - Initial version - December 2018
# 

import jarray
import inspect
import os
import binascii

from java.util import UUID
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from java.util import ArrayList
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.datamodel import CommunicationsManager 
from org.sleuthkit.datamodel import Relationship
from org.sleuthkit.datamodel import Account



# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ProcessTeraCopyDbIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Teracopy"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses Teracopy Db"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessTeraCopyDbIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessTeraCopyDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ProcessTeraCopyDbIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")
        self.stringColumns = (('TSK_OPERATION_STATE','Operation State'), ('TSK_FILE_SIZE', 'Size (Bytes)'), \
                              ('TSK_ATTRIBUTES','Attributes'), ('TSK_ISFOLDER','Is Folder'), \
                              ('TSK_SOURCE_CRC','Source CRC'), ('TSK_TARGET_CRC','Target CRC'), \
                              ('TSK_MESSAGE','Message'), ('TSK_OPERATION_TYPE','Operation Type'), \
                              ('TSK_HISTORY_FILE','History File'), ('TSK_SOURCE_LOCATION', 'File Source Location'), \
                              ('TSK_TARGET_LOCATION', 'Target Location'), ('TSK_FILE_PATH', 'File Path'))

        self.dateColumns = []
                              
        self.dateColumn = ('TSK_DATETIME_START', 'TSK_DATETIME_ACCESSED', 'TSK_DATETIME_CREATED', 'TSK_DATETIME_MODIFIED', \
                           'TSK_ACTCACHE_CRT_CLOUD', 'TSK_ACTCACHE_LAST_MOD_CLIENT', 'TSK_ACTCACHE_ORIG_LMOC')
                           
    def startUp(self, context):
        self.context = context
        pass
        
    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        #progressBar.switchToIndeterminate()
        
        # get current case and the TeraCopy main.db abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "main.db", "%TeraCopy%")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
        moduleName = ProcessTeraCopyDbIngestModuleFactory.moduleName

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "TeraCopy")
        #self.log(Level.INFO, "create Directory " + moduleDirectory)
        try:
		    os.mkdir(temporaryDirectory)
        except:
            pass
            #self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)
			
        filePathId = {}
        for file in files:
            fileName = file.getName()
            if fileName.endswith(".db"):
                filePathId[file.getParentPath()] = file.getId()
                #self.log(Level.INFO, "file path and id ==> " + str(file.getParentPath()) + " <> " + str(file.getId()) + " <> " + str(fileName))
            
        if numFiles > 0:
            for artifact in self.stringColumns:
                try:
                    attID = skCase.addArtifactAttributeType(artifact[0], BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, artifact[1])
                    #self.log(Level.INFO, "attribute id for " + artifact[0] + " == " + str(attID))
                except:		
                    self.log(Level.INFO, "Attributes Creation Error, " + artifact[0] + " ==> ")
            for artifact in self.dateColumns:
                try:
                    attID = skCase.addArtifactAttributeType(artifact[0], BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, artifact[1])
                    #self.log(Level.INFO, "attribute id for " + artifact[0] + " == " + str(attID))
                except:		
                    self.log(Level.INFO, "Attributes Creation Error, " + artifact[0] + " ==> ")
            try:
                #self.log(Level.INFO, "Begin Create New Artifacts ==> TSK_TERACOPY_DB")
                artID_art = skCase.addArtifactType("TSK_TERACOPY_DB", "Teracopy History DB")
            except:		
                self.log(Level.INFO, "Artifacts Creation Error, artifact TSK_TERACOPY_DB exists. ==> ")

        artTeraCopyId = skCase.getArtifactTypeID("TSK_TERACOPY_DB")
        #self.log(Level.INFO, "Artifact id ==> " + str(artTeraCopyId))
        artTeraCopy = skCase.getArtifactType("TSK_TERACOPY_DB")

        moduleName = ProcessTeraCopyDbIngestModuleFactory.moduleName
                    
                    
        # Write out each users store.vol file and process it.
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the file locally. Use file id as name to reduce collisions
            fileId = filePathId[file.getParentPath()]
            extractedFile = os.path.join(temporaryDirectory, str(fileId) + "-" + file.getName())
            
            ContentUtils.writeToFile(file, File(extractedFile))

            userpath = file.getParentPath()
            username = userpath.split('/')
            #self.log(Level.INFO, "Getting Username " + username[2]   )

            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % extractedFile)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + extractedFile + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("select name TSK_HISTORY_FILE, SOURCE TSK_SOURCE_LOCATION, target TSK_TARGET_LOCATION, " + \
                                              " CASE operation WHEN 1 THEN 'Copy' WHEN 2 THEN 'Move' WHEN 3 THEN 'Test' WHEN 6 THEN " + \
                                              " 'Delete' END TSK_OPERATION_TYPE, strftime('%s', started) TSK_DATETIME_START, " + \
                                              " strftime('%s', finished) TSK_DATETIME_END from list")
                #self.log(Level.INFO, "query list table")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for list tables (" + e.getMessage() + ") ")
                return IngestModule.ProcessResult.OK

            while resultSet.next():
                historyFile = resultSet.getString("TSK_HISTORY_FILE")
                fileManagerHist = Case.getCurrentCase().getServices().getFileManager()
                histFiles = fileManagerHist.findFiles(dataSource, historyFile + "%", "%TeraCopy%")
                numHistFiles = len(histFiles)
                #self.log(Level.INFO, "Number of files ==> " + str(numHistFiles))
                #self.log(Level.INFO, "Files ==> " + str(histFiles))
                sourceLocation = resultSet.getString('TSK_SOURCE_LOCATION')
                targetLocation = resultSet.getString('TSK_TARGET_LOCATION')
                operationType = resultSet.getString('TSK_OPERATION_TYPE')
                startTime = resultSet.getInt('TSK_DATETIME_START')
                endTime = resultSet.getInt('TSK_DATETIME_END')
                for histFile in histFiles:
                    extractedHistFile = os.path.join(temporaryDirectory, str(histFile.getId()) + "-" + historyFile)
                    #self.log(Level.INFO, "History File ==> " + extractedHistFile)
                    ContentUtils.writeToFile(histFile, File(extractedHistFile))

                    try: 
#                        Class.forName("org.sqlite.JDBC").newInstance()
                        dbConnHist = DriverManager.getConnection("jdbc:sqlite:%s"  % extractedHistFile)
                    except SQLException as e:
                        self.log(Level.INFO, "Could not open database file (not SQLite) " + extractedHistFile + " (" + e.getMessage() + ")")
                        return IngestModule.ProcessResult.OK

                    try:
                        stmtHist = dbConnHist.createStatement()
                        resultSetHist = stmtHist.executeQuery("SELECT SOURCE TSK_FILE_PATH, CASE State WHEN 0 THEN 'Added' " + \ 
                                                              " WHEN 1 THEN 'OK' WHEN 2 THEN 'Verified' " + \
                                                              " WHEN 3 THEN 'Error' WHEN 4 THEN 'Skipped' WHEN 5 THEN 'Deleted' " + \
                                                              " WHEN 6 THEN 'Moved' END TSK_OPERATION_STATE, SIZE TSK_FILE_SIZE, " + \
                                                              " Attributes TSK_ATTRIBUTES, CASE IsFolder WHEN 0 THEN '' WHEN 1 THEN 'Yes' " + \
                                                              " END TSK_ISFOLDER, strftime('%s', Creation) TSK_DATETIME_CREATED, " + \
                                                              " strftime('%s', Access) TSK_DATETIME_ACCESSED, " + \
                                                              " strftime('%s', Write) TSK_DATETIME_MODIFIED, " + \
                                                              " SourceCRC TSK_SOURCE_CRC, TargetCRC TSK_TARGET_CRC, Message TSK_MESSAGE " + \
                                                              " FROM Files ")
                        #self.log(Level.INFO, "query list table")
                    except SQLException as e:
                        self.log(Level.INFO, "Error querying database for list tables (" + e.getMessage() + ") ")
                        return IngestModule.ProcessResult.OK

                    meta = resultSetHist.getMetaData()
                    columnCount = meta.getColumnCount()
                    columnNames = []
            #        self.log(Level.INFO, "Number of Columns in the table ==> " + str(columnCount))
                    for x in range (1, columnCount + 1):
            #            self.log(Level.INFO, "Column Count ==> " + str(x))
            #            self.log(Level.INFO, "Column Name ==> " + meta.getColumnLabel(x))
                        columnNames.append(meta.getColumnLabel(x))

                    while resultSetHist.next():
                    
                        ## Cycle through each row and get the data
            ##            self.log(Level.INFO, "Start PRocessing")
                        # while resultSet.next():
                        try:
                            artifact = file.newArtifact(artTeraCopyId)
                            attributes = ArrayList()
                            attributes.add(BlackboardAttribute(skCase.getAttributeType('TSK_HISTORY_FILE'), moduleName, historyFile))
                            attributes.add(BlackboardAttribute(skCase.getAttributeType('TSK_SOURCE_LOCATION'), moduleName, sourceLocation))
                            attributes.add(BlackboardAttribute(skCase.getAttributeType('TSK_TARGET_LOCATION'), moduleName, targetLocation))
                            attributes.add(BlackboardAttribute(skCase.getAttributeType('TSK_OPERATION_TYPE'), moduleName, operationType))
                            attributes.add(BlackboardAttribute(skCase.getAttributeType('TSK_DATETIME_START'), moduleName, startTime))
                            attributes.add(BlackboardAttribute(skCase.getAttributeType('TSK_DATETIME_END'), moduleName, endTime))
                            for x in range(0, columnCount):
                                if columnNames[x] in self.dateColumn:
        #                            self.log(Level.INFO, "Date ColumnName ==> " + columnNames[x])
                                    attributes.add(BlackboardAttribute(skCase.getAttributeType(columnNames[x]), moduleName, resultSetHist.getInt(columnNames[x])))
                                else:
        #                            self.log(Level.INFO, "ColumnName ==> " + columnNames[x])
                                    attributes.add(BlackboardAttribute(skCase.getAttributeType(columnNames[x]), moduleName, resultSetHist.getString(columnNames[x])))
                                
        #                        self.log(Level.INFO, "Column Count ==> " + str(x))
                                
                            artifact.addAttributes(attributes)

                            # index the artifact for keyword search
                            try:
                                blackboard.indexArtifact(artifact)
                            except:
                                pass
                        except SQLException as e:
                            self.log(Level.INFO, "Error getting values from files table (" + e.getMessage() + ")")

               # Close the database statement
                try:
                    stmtHist.close()
                    dbConnHist.close()
                except:
                    pass                    
            try:
                stmt.close()
                dbConn.close()
            except:
                pass                    
                

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "TeraCopy DB", " TeraCopy DB Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
      
