# This python autopsy module will open Google Takeout files from a logical datasource
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

# Google_Takeout.
# May 2020
# 
# Comments 
#   Version 1.0 - Initial version - May 2020
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE

from java.util import UUID
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
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
class GoogleTakeoutIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Google Takeout"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Extract Files from GoogleTakeout To a New Data Source"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return GoogleTakeoutIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class GoogleTakeoutIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(GoogleTakeoutIngestModuleFactory.moduleName)

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
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "takeout.exe")
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("Windows Executable was not found in module folder")

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        #raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Get the temp directory and create the sub directory
        modDir = os.path.join(Case.getCurrentCase().getModulesOutputDirAbsPath(), "GoogleTakeout")
        try:
		    os.mkdir(modDir)
        except:
		    self.log(Level.INFO, "Google Takout Directory already Exists " + modDir)

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
            if imageFile != None:
                progressBar.progress("Extracting " + file.getName())
                self.log(Level.INFO, "Running program ==> " + self.path_to_exe + " " + imageFile + " " + modDir)
                pipe = Popen([self.path_to_exe, imageFile, modDir], stdout=PIPE, stderr=PIPE) 
                outText = pipe.communicate()[0]
                # Because of a bug in Python version can't run this code and have to run external program instead
                #if ".zip" in imageFile.lower():
                #    zipFile = zipfile.ZipFile(file=imageFile, mode="r", allowZip64=True)
                #    for zip in zipFile.namelist():
                #        zipFile.extractAll(member=zip)


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
        
        progressBar.progress("Adding Takeout files to GoogleTakeout Data Source")
        
        # Add data source with files
        newDataSource = fileManager.addLocalFilesDataSource(str(device_id), "GoogleTakeout", "", dir_list, progress_updater)
        
        newDataSources.append(newDataSource.getRootDirectory())
       
        # Get the files that were added
        files_added = progress_updater.getFiles()
        
        for file_added in files_added:
            progressBar.progress("Adding Takeout files to new data source")
            skcase_data.notifyDataSourceAdded(file_added, device_id)
            #self.log(Level.INFO, "Fire Module1: ==> " + str(file_added))

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "GoogleTakeoutSettings", " GoogleTakeoutSettings Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

   