# This python autopsy module will open a Access Data AD1 file from a logical datasource
# and extract their content to the Module directory then create a new datasource with
# all the files from all the takeout files.
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

# AD1_Extractor.
# Junw 2020
# 
# Comments 
#   Version 1.0 - Initial version - June 2020
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE
import shutil

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
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
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
from org.sleuthkit.autopsy.casemodule import AddLocalFilesTask
from org.sleuthkit.autopsy.casemodule.services.FileManager import FileAddProgressUpdater
from org.sleuthkit.autopsy.ingest import ModuleContentEvent;

class ProgressUpdater(FileAddProgressUpdater):

    def __init__(self):
        self.files = []
        pass
    
    def fileAdded(self, newfile):
        self.files.append(newfile)
        
    def getFiles(self):
        return self.files

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class AD1ExtractorIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "AD1 Extractor"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Extract Files from AD1 Files To a New Data Source"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return AD1ExtractorIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class AD1ExtractorIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(AD1ExtractorIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        pass

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        if PlatformUtil.isWindowsOS():
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract_ad1.exe")
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("Windows Executable was not found in module folder")

        self.sqlStatement = "select file_name, ad1_path_name, date_created, date_modified, date_accessed, md5_hash, sha1_hash from ad1_info where ad1_item_type = 0;"

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        #raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Get the temp directory and create the sub directory
        modDir = os.path.join(Case.getCurrentCase().getModulesOutputDirAbsPath(), "AD1Extractor")
        try:
		    os.mkdir(modDir)
        except:
		    self.log(Level.INFO, "AD1 Extractor Directory already Exists " + modDir)

        moduleName = AD1ExtractorIngestModuleFactory.moduleName

        # get the current case
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%", "/")
        numFiles = len(files)
        self.log(Level.INFO, "Number of files to process ==> " + str(numFiles))
        for file in files:
            self.log(Level.INFO, "File name to process is ==> " + file.getName())
            self.log(Level.INFO, "File name to process is ==> " + str(file.getLocalAbsPath()))
            imageFile = file.getLocalAbsPath()
            if ((imageFile != None) or (not file.isDir())):
                if ".ad1" in imageFile.lower():
                    progressBar.progress("Extracting " + file.getName())
                    filename, file_extension = os.path.splitext(file.getName())
                    self.log(Level.INFO, "Running program ==> " + self.path_to_exe + " " + imageFile + " " + modDir + " " + os.path.join(modDir, filename + ".db3"))
                    pipe = Popen([self.path_to_exe, imageFile, modDir, os.path.join(modDir, filename + ".db3")], stdout=PIPE, stderr=PIPE) 
                    outText = pipe.communicate()[0]

                    try:
                        self.log(Level.INFO, "Begin Create New Artifacts")
                        artIdAD1 = skCase.addArtifactType( "AD1_EXTRACTOR", "AD1 Extraction")
                    except:		
                        self.log(Level.INFO, "Artifacts Creation Error, Artifact AD1_EXTRACTOR may exist. ==> ")
                        artIdAD1 = skCase.getArtifactTypeID("AD1_EXTRACTOR")

                    try: 
                        Class.forName("org.sqlite.JDBC").newInstance()
                        dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % os.path.join(modDir, filename + ".db3"))
                    except SQLException as e:
                        self.log(Level.INFO, "Could not open database file (not SQLite) " + os.path.join(modDir, filename + ".db3") + " (" + e.getMessage() + ")")
                        return IngestModule.ProcessResult.OK

                    try:
                        stmt = dbConn.createStatement()
                        resultSet = stmt.executeQuery(self.sqlStatement)
                        self.log(Level.INFO, "query ad1_info")
                    except SQLException as e:
                        self.log(Level.INFO, "Error querying database for ad1_info tables (" + e.getMessage() + ") ")
                        return IngestModule.ProcessResult.OK

                    # Cycle through each row and get the installed programs and install time
                    while resultSet.next():
                        try: 
                            artAD1 = file.newArtifact(artIdAD1)
                            attributes = ArrayList()
                            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, moduleName, resultSet.getString("file_name")))
                            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEMP_DIR, moduleName, resultSet.getString("ad1_path_name")))
                            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, moduleName, resultSet.getInt("date_created")))
                            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED, moduleName, resultSet.getInt("date_modified")))
                            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, moduleName, resultSet.getInt("date_accessed")))
                            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_HASH_MD5, moduleName, resultSet.getString("md5_hash")))
                            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_HASH_SHA1, moduleName, resultSet.getString("sha1_hash")))
               
                            artAD1.addAttributes(attributes)

                            # index the artifact for keyword search
                            try:
                                blackboard.postArtifact(artAD1)
                            except:
                                pass
                        except SQLException as e:
                            self.log(Level.INFO, "Error getting values from AD1tables (" + e.getMessage() + ")")

               # Close the database statement
                try:
                    stmt.close()
                    dbConn.close()
                except:
                    pass                    
                   
        dir_list = []
        dir_list.append(modDir)
    
        services = IngestServices.getInstance()
    
        progress_updater = ProgressUpdater()  
        newDataSources = []        
     
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        skcase_data = Case.getCurrentCase()
    
        # Get a Unique device id using uuid
        device_id = UUID.randomUUID()
        self.log(Level.INFO, "device id: ==> " + str(device_id))

        skcase_data.notifyAddingDataSource(device_id)
        
        progressBar.progress("Adding Takeout files to AD1Extractor Data Source")
        
        # Add data source with files
        newDataSource = fileManager.addLocalFilesDataSource(str(device_id), "AD1", "", dir_list, progress_updater)
        
        newDataSources.append(newDataSource.getRootDirectory())
       
        # Get the files that were added
        files_added = progress_updater.getFiles()
        
        for file_added in files_added:
            progressBar.progress("Adding AD1 extracted files to new data source")
            skcase_data.notifyDataSourceAdded(file_added, device_id)
            #self.log(Level.INFO, "Fire Module1: ==> " + str(file_added))

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "AD1ExtractorSettings", " AD1Extractors Has Been Run " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

   