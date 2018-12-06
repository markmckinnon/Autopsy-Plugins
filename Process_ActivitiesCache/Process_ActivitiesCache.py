# This python autopsy module will process the ActivitiesCache.db SQLite database
# and add the data to extracted content
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

# Process_ActivitiesCache module to process ActivitiesCache Database.
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
class ProcessActivitiesCacheIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "ActivitiesCache"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses ActivitiesCache Db"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessActivitiesCacheIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessActivitiesCacheIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ProcessActivitiesCacheIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")
        self.stringColumns = (('TSK_ACTCACHE_ID','ActivityCache Id'), ('TSK_ACTCACHE_APP_ID', 'Activity Cache App Id'), \
                              ('TSK_ACTCACHE_PAYLOAD','Activity Cache Payload'), ('TSK_ACTCACHE_ACT_TYPE','Activity Type'), \
                              ('TSK_ACTCACHE_LOCAL_ONLY','Is Local Only'), ('TSK_ACTCACHE_ETAG','ETag'), \
                              ('TSK_ACTCACHE_PKGID_HASH','Package Id Hash'), ('TSK_ACTCACHE_PLAT_DEVID','Platform Device Id'), \
                              ('TSK_ACTCACHE_STATUS','Activity Cache Status'))

        self.dateColumns = (('TSK_ACTCACHE_ST_TIME','Start Time'), ('TSK_ACTCACHE_ENDTIME','End Time'), \
                            ('TSK_ACTCACHE_LAST_MOD','Last Modified Time'), ('TSK_ACTCACHE_EXP_TIME','Expiration Time'), \
                            ('TSK_ACTCACHE_CRT_CLOUD','Created In Cloud'), ('TSK_ACTCACHE_LAST_MOD_CLIENT','Last Modified On Client'), \
                            ('TSK_ACTCACHE_ORIG_LMOC','Original Last Modified On Client'))
        self.dateColumn = ('TSK_ACTCACHE_ST_TIME', 'TSK_ACTCACHE_ENDTIME', 'TSK_ACTCACHE_LAST_MOD', 'TSK_ACTCACHE_EXP_TIME', \
                           'TSK_ACTCACHE_CRT_CLOUD', 'TSK_ACTCACHE_LAST_MOD_CLIENT', 'TSK_ACTCACHE_ORIG_LMOC')
                           
    def startUp(self, context):
        self.context = context
        pass
        
    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        #progressBar.switchToIndeterminate()
        
        # get current case and the ActivitiesCache abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "ActivitiesCache%")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
        moduleName = ProcessActivitiesCacheIngestModuleFactory.moduleName

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "ActivitiesCache")
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
                self.log(Level.INFO, "file path and id ==> " + str(file.getParentPath()) + " <> " + str(file.getId()) + " <> " + str(fileName))
            
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
                #self.log(Level.INFO, "Begin Create New Artifacts ==> TSK_ACTCACHE_DB")
                artID_art = skCase.addArtifactType("TSK_ACTCACHE_DB", "Activities Cache Timeline DB")
            except:		
                self.log(Level.INFO, "Artifacts Creation Error, artifact TSK_ACTCACHE_DB exists. ==> ")

                    
                    
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

#        for file in files:
            fileName = file.getName()	
            if fileName.endswith(".db"):
                extractedFile = os.path.join(temporaryDirectory, str(filePathId[file.getParentPath()]) + "-" + file.getName())

                artActCacheId = skCase.getArtifactTypeID("TSK_ACTCACHE_DB")
                self.log(Level.INFO, "Artifact id ==> " + str(artActCacheId))
                artActCache = skCase.getArtifactType("TSK_ACTCACHE_DB")

                moduleName = ProcessActivitiesCacheIngestModuleFactory.moduleName
                
                try: 
                    Class.forName("org.sqlite.JDBC").newInstance()
                    dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % extractedFile)
                except SQLException as e:
                    self.log(Level.INFO, "Could not open database file (not SQLite) " + extractedFile + " (" + e.getMessage() + ")")
                    return IngestModule.ProcessResult.OK

                try:
                    stmt = dbConn.createStatement()
                    resultSet = stmt.executeQuery("select hex(id) TSK_ACTCACHE_ID, appId TSK_ACTCACHE_APP_ID, " + \
                                                  " cast(Payload as Text) TSK_ACTCACHE_PAYLOAD, " + \
                                                  " ActivityType TSK_ACTCACHE_ACT_TYPE, ActivityStatus TSK_ACTCACHE_STATUS, " + \
                                                  " startTime TSK_ACTCACHE_ST_TIME, EndTime TSK_ACTCACHE_ENDTIME, " + \
                                                  " LastModifiedTime TSK_ACTCACHE_LAST_MOD, ExpirationTime TSK_ACTCACHE_EXP_TIME, " + \
                                                  " createdInCloud TSK_ACTCACHE_CRT_CLOUD, " + \
                                                  " LastModifiedOnClient TSK_ACTCACHE_LAST_MOD_CLIENT, " + \
                                                  " OriginalLastModifiedOnClient TSK_ACTCACHE_ORIG_LMOC, " + \
                                                  " isLocalOnly TSK_ACTCACHE_LOCAL_ONLY, Etag TSK_ACTCACHE_ETAG, " + \
                                                  " packageIdHash TSK_ACTCACHE_PKGID_HASH, " + \
                                                  " PlatformDeviceId TSK_ACTCACHE_PLAT_DEVID from smartlookup")
                    #self.log(Level.INFO, "query smartlookup table")
                except SQLException as e:
                    self.log(Level.INFO, "Error querying database for smartlookup tables (" + e.getMessage() + ") ")
                    return IngestModule.ProcessResult.OK

                meta = resultSet.getMetaData()
                columnCount = meta.getColumnCount()
                columnNames = []
                self.log(Level.INFO, "Number of Columns in the table ==> " + str(columnCount))
                for x in range (1, columnCount + 1):
                    #self.log(Level.INFO, "Column Count ==> " + str(x))
                    #self.log(Level.INFO, "Column Name ==> " + meta.getColumnLabel(x))
                    columnNames.append(meta.getColumnLabel(x))
                            
                # Cycle through each row and get the data
                self.log(Level.INFO, "Start PRocessing")
                while resultSet.next():
                    try:
                        artifact = file.newArtifact(artActCacheId)
                        attributes = ArrayList()
                        attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), moduleName, username[2]))
                        for x in range(0, columnCount):
                            if columnNames[x] in self.dateColumn:
                                #self.log(Level.INFO, "Date ColumnName ==> " + columnNames[x])
                                attributes.add(BlackboardAttribute(skCase.getAttributeType(columnNames[x]), moduleName, resultSet.getInt(columnNames[x])))
                            else:
                                if columnNames[x] == "TSK_ACTCACHE_ID":
                                   #self.log(Level.INFO, "ColumnName ==> " + columnNames[x])
                                   attributes.add(BlackboardAttribute(skCase.getAttributeType(columnNames[x]), moduleName, resultSet.getString(columnNames[x])))
                                else:
                                   attributes.add(BlackboardAttribute(skCase.getAttributeType(columnNames[x]), moduleName, resultSet.getString(columnNames[x])))
                            
                            #self.log(Level.INFO, "Column Count ==> " + str(x))
                            
                        artifact.addAttributes(attributes)

                        # index the artifact for keyword search
                        try:
                            blackboard.indexArtifact(artifact)
                        except:
                            pass
                    except SQLException as e:
                        self.log(Level.INFO, "Error getting values from smartlookup table (" + e.getMessage() + ")")

               # Close the database statement
                try:
                    stmt.close()
                    dbConn.close()
                except:
                    pass                    
			

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "ActivitiesCache", " ActivitiesCache's Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
      
