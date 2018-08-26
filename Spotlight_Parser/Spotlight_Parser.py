# This python autopsy module will process Spotlight database from Mac osx.  It uses 
# the program spotlight_parser from Yogesh Khatri https://github.com/ydkhatri/spotlight_parser
# to parse the store.db or .store.db file into a SQLite database and then import
# the data into Autopsy.
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

# Spotlight_Parser module to process Mac osx spotlight database.
# July 2018
# 
# Comments 
#   Version 1.0 - Initial version - July 2018
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE

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
class ProcessSpotlightIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Spotlight Parser"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses Mac osx Spotlight Db"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessSpotlightIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessSpotlightIngestModule(DataSourceIngestModule):

#    _logger = Logger.getLogger(ProcessSpotlightIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")

    def startUp(self, context):
        self.context = context

        # Get path to executable based on where this script is run from.
        # Assumes executable is in same folder as script
        # Verify it is there before any ingest starts
        if PlatformUtil.isWindowsOS(): 
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spotlight_parser.exe")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("spotlight_parser.exe was not found in module folder")
        else:        
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spotlight_parser")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("spotlight_parser was not found in module folder")

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "store.db", "Store-V2")
        numFiles = len(files)
        #self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        moduleDirectory = os.path.join(Case.getCurrentCase().getModuleDirectory(), "spotlight")
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "spotlight")
        #self.log(Level.INFO, "create Directory " + moduleDirectory)
        try:
		    os.mkdir(moduleDirectory)
        except:
	        pass	
            #self.log(Level.INFO, "Module directory already exists " + moduleDirectory)
        try:
		    os.mkdir(temporaryDirectory)
        except:
            pass
            #self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)
			
        # Write out each users store.db file and process it.
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the file locally. Use file id as name to reduce collisions
            extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
            ContentUtils.writeToFile(file, File(extractedFile))
            self.processSpotlightFile(extractedFile, moduleDirectory)

        for file in files:	
           # Open the DB using JDBC
           lclDbPath = os.path.join(moduleDirectory, "spotlight_db.db3")
           #self.log(Level.INFO, "Path to the mail database is ==> " + lclDbPath)
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               #self.log(Level.INFO, "Could not open database file (not SQLite) " + lclDbPath + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
 
           self.processSpotlightDb(dbConn, file)

           # Clean up
        try:
            dbConn.close()
            shutil.rmtree(temporaryDirectory)
        except:
		    self.log(Level.INFO, "removal of spotlight database failed " + temporaryDirectory)
  
    
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Spotlight Parser", " Spotlight Db Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    def processSpotlightFile(self, extractedFile, moduleDirectory):

        #self.log(Level.INFO, "Running program ==> " + self.pathToExe + " " + extractedFile + databaseFile)
        pipe = Popen([self.pathToExe, "-p", "spotlight", extractedFile, moduleDirectory], stdout=PIPE, stderr=PIPE)
        outputFromRun = pipe.communicate()[0]
        #pass           

    def processSpotlightDb(self, dbConn, file):

        skCase = Case.getCurrentCase().getSleuthkitCase();
        
        try:
            self.log(Level.INFO, "Begin Create New Artifacts")
            artID = skCase.addArtifactType("TSK_SPOTLIGHT", "Mac OS Spotlight Data")
        except:		
            self.log(Level.INFO, "Artifacts Creation Error, TSK_SPOTLIGHT some artifacts may not exist now. ==> ")
 
        columnDefs = []

        sqlPragma = 'Pragma Table_Info (spotlight_data)'
       
        try:
            sqlStmtPragma = dbConn.createStatement()
            resultSetPragma = sqlStmtPragma.executeQuery(sqlPragma)
        except:
            return IngestModule.ProcessResult.OK
                
        while resultSetPragma.next():
            columnDef = []
            attributeName = 'TSK_' + resultSetPragma.getString("name").upper()
            columnName = resultSetPragma.getString("name").upper()
            columnDef.append(columnName)
            columnDef.append(resultSetPragma.getString("type").upper())
            if resultSetPragma.getString("type").upper() == "TEXT":
                try:
                    attID_ex1 = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, columnName)
                except:		
                    self.log(Level.INFO, "Attributes Creation Error, " + attributeName + " ==> ")
            else:
                try:
                    attID_ex1 = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, columnName)
                except:		
                    self.log(Level.INFO, "Attributes Creation Error, " + attributeName + " ==> ")
            
            columnDef.append(attributeName)
            columnDef.append(skCase.getAttributeType(attributeName))
            columnDefs.append(columnDef)
            
 
        sqlStatement = 'select * from spotlight_data'


        #self.log(Level.INFO, "SQL Statement ==> ")
        # Query the contacts table in the database and get all columns. 
        try:
            sqlStmt = dbConn.createStatement()
            resultSet = sqlStmt.executeQuery(sqlStatement)
            #self.log(Level.INFO, "query message table")
        except SQLException as e:
            #self.log(Level.INFO, "Error querying database for message table (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK


        artIdSpotlight = skCase.getArtifactTypeID("TSK_SPOTLIGHT")
        artIdSpotlightType = skCase.getArtifactType("TSK_SPOTLIGHT")
        
        moduleName = ProcessSpotlightIngestModuleFactory.moduleName
         
        # Cycle through each row and create artifacts
        while resultSet.next():
           
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            try: 
                artSpotlight = file.newArtifact(artIdSpotlight)
                attributes = ArrayList()
                for columnName in columnDefs:
                    self.log(Level.INFO, "Column Info ==> " + str(columnName[0]) + "    " + str(columnName[1]) + "     " + str(columnName[2]) + "    " + str(columnName[3]))
                    attId = skCase.getAttributeType(columnName[2])
                    self.log(Level.INFO, "Column Info ==> " + str(attId))                    
                    if columnName[1] == "TEXT":
                        attributes.add(BlackboardAttribute(attId, moduleName, resultSet.getString(columnName[0])))
                    else:
                        attributes.add(BlackboardAttribute(attId, moduleName, long(resultSet.getInt(columnName[0]))))
                artSpotlight.addAttributes(attributes)        
                    
                try:
                    blackboard.indexArtifact(artSpotlight)
                except:
                    pass
#                    self._logger.log(Level.SEVERE, "Error indexing artifact " + artEmail.getDisplayName())

            except SQLException as e:
                self.log(Level.INFO, "Error getting values from message table (" + e.getMessage() + ")")

        # Close the database statement
        sqlStmt.close()
        sqlStmtPragma.close()
       
        # fire event to let the system know new data was added
        #IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ProcessSpotlightIngestModuleFactory.moduleName, \
        #                                 artIdEmailType, None))

       
