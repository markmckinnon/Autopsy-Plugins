# This python autopsy module will parse Leveldb databases
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

# Leveldb_Parser module to process LevelDB's.
# October 2020
# 
# Comments 
#   Version 1.0 - Initial version - October 2020
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE
import csv

from java.lang import Class
from java.lang import System
#from java.sql  import DriverManager, SQLException
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
#from org.sleuthkit.datamodel import CommunicationsManager 
#from org.sleuthkit.datamodel import Relationship
#from org.sleuthkit.datamodel import Account



# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class LeveldbParserIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "LevelDB Parser"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses LevelDb's"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return LeveldbParserIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class LeveldbParserIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(LeveldbParserIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")
        self.fbPeopleDict = {}
        self.chatMessages = []
        self.fbOwnerId = 0

    def startUp(self, context):
        self.context = context
        if PlatformUtil.isWindowsOS(): 
           self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leveldb-dump.exe")
#           self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leveldb_Parser.exe")
           if not os.path.exists(self.pathToExe):
               raise IngestModuleException("fb_chat.exe was not found in module folder")
        else:
           pass       
#           self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fb_chat")
#           if not os.path.exists(self.pathToExe):
#               raise IngestModuleException("fb_chat was not found in module folder")

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "manifest-%")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

        artifactId = 0

        try:
             artId = skCase.addArtifactType("TSK_LEVELDB", "LevelDb Database(s)")
             artifactId = skCase.getArtifactTypeID("TSK_LEVELDB")
        except:		
             artifactId = skCase.getArtifactTypeID("TSK_LEVELDB")
             self.log(Level.INFO, "Artifacts Creation Error for artifact ==> TSK_LEVELDB")


		# Create Event Log directory in temp directory, if it exists then continue on processing		
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "LevelDb")
        #self.log(Level.INFO, "create Directory " + moduleDirectory)
        try:
		    os.mkdir(temporaryDirectory)
        except:
            pass
            #self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)
			
        # Write out each users store.vol file and process it.
        for file in files:
            if "-slack" not in file.getName():
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Processing Path: " + file.getParentPath())
                fileCount += 1

                manifestDirectory = os.path.join(temporaryDirectory, str(file.getId()))
                try:
                    os.mkdir(manifestDirectory)
                except:
                    self.log(Level.INFO, "Temporary directory already exists " + manifestDirectory)

                levelDbFiles = fileManager.findFilesByParentPath(dataSource.getId(), file.getParentPath())
                levelDbFileNum = len(levelDbFiles)
                self.log(Level.INFO, "found " + str(levelDbFileNum) + " files")
                
                for levelDbFile in levelDbFiles:

                    # Save the file locally. Use file id as name to reduce collisions
                    self.log(Level.INFO, "Copying file " + levelDbFile.getName() + " to temp")
                    if levelDbFile.getName() == "." or levelDbFile.getName() == ".." or "-slack" in levelDbFile.getName():
                        self.log(Level.INFO, "Not a valid file to copy")
                    else:                    
            
                        extractedLevelDbFile = os.path.join(manifestDirectory, levelDbFile.getName())
                        ContentUtils.writeToFile(levelDbFile, File(extractedLevelDbFile))
                        #os.remove(extractedFile)

                sqliteDbFile = os.path.join(temporaryDirectory, str(file.getId()) + ".db3")
                csvOutFile = os.path.join(temporaryDirectory, str(file.getId()))
                self.log(Level.INFO, str(self.pathToExe) + " " + str(manifestDirectory) + " " + str(csvOutFile))
    #           self.log(Level.INFO, str(self.pathToExe) + " " + str(manifestDirectory) + " " + str(sqliteDbFile) + " " + str(csvOutFile))
    #            pipe = Popen([self.pathToExe, manifestDirectory, sqliteDbFile + ".db3", csvOutFile + ".csv"], stdout=PIPE, stderr=PIPE)
                pipe = Popen([self.pathToExe, manifestDirectory, csvOutFile], stdout=PIPE, stderr=PIPE)
                outputFromRun = pipe.communicate()[0]
                self.log(Level.INFO, "Output from Run is ==> " + outputFromRun)

                attribute_names = ["TSK_NAME", "TSK_VALUE"]
                with open(csvOutFile + ".csv", 'rU') as csvfile:
                    csvreader = csv.reader(csvfile, delimiter=',', quotechar='|')
                    for row in csvreader:
                        art = file.newArtifact(artifactId)
                        for (data, head) in zip(row, attribute_names): 
                            art.addAttribute(BlackboardAttribute(skCase.getAttributeType(head), LeveldbParserIngestModuleFactory.moduleName, data))
                                #self.log(Level.INFO, "artifact_created. ==> " + "TSK_CSV_" + col_name.upper() + " =====> " + data)
                        art.addAttribute(BlackboardAttribute(skCase.getAttributeType("TSK_PATH"), LeveldbParserIngestModuleFactory.moduleName, file.getParentPath()))
            

            #self.processFbChat(databaseFile)
            #self.processChats(skCase, file)
            #os.remove(extractedFile)
 
			

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "LevelDb Parser", " LevelDb's Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

