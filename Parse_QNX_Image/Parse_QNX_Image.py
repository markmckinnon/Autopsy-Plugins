# This python autopsy module will process a QNX image and create a pull out 
# all files and recreate the filesystem as a new datasource.  This uses a modified
# version from this github repo https://github.com/ReFirmLabs/qnx6-extractor
# to parse the image and export the files to the case module output folder so the
# files can be added back into the case.
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

# Parse QNX Image.
# July 2021
# 
# Comments 
#   Version 1.0 - Initial version - July 2021
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
from org.sleuthkit.datamodel import Image
from org.sleuthkit.datamodel.TskData import DbType
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestManager
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest import ModuleContentEvent
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
    
class ParseQNXImageModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Parse QNX Image"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Extract QNX image to a new data source"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseQNXImageModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ParseQNXImageModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseQNXImageModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_Logical_Files = []

    def startUp(self, context):
        self.context = context
       
        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "process_QNX6_Image.exe")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("process_QNX6_Image.exe File to Run/execute does not exist.")

        pass

    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        skCase = Case.getCurrentCase().getSleuthkitCase();
        
        self.log(Level.INFO, "Starting Processing of Image")

        image_names = dataSource.getPaths()
        self.log(Level.INFO, "Image names ==> " + str(image_names[0]))
        image_name = str(image_names[0])
        
  		# Create VSS directory in ModuleOutput directory, if it exists then continue on processing		
        Mod_Dir = Case.getCurrentCase().getModulesOutputDirAbsPath()
        self.log(Level.INFO, "create Directory " + Mod_Dir)
        qnx6_output = os.path.join(Mod_Dir, "QNX6")

        try:
		    os.mkdir(vss_output)
        except:
		    self.log(Level.INFO, "QNX6 already exists " + Mod_Dir)
            
        # Run the Processing/Extraction process
        self.log(Level.INFO, "Running prog ==> " + self.path_to_exe + " " + image_name + " " + qnx6_output)
        pipe = Popen([self.path_to_exe, image_name, qnx6_output], stdout=PIPE, stderr=PIPE)
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text)               

        dir_list = []
        dir_list.append(qnx6_output)
        
        services = IngestServices.getInstance()
        
        progress_updater = ProgressUpdater()  
        newDataSources = []        
         
        # skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        skcase_data = Case.getCurrentCase()
        
        # Get a Unique device id using uuid
        device_id = UUID.randomUUID()
        self.log(Level.INFO, "device id: ==> " + str(device_id))

        skcase_data.notifyAddingDataSource(device_id)
            
        # Add data source with files
        newDataSource = fileManager.addLocalFilesDataSource(str(device_id), "QNX6-Image-File", "", dir_list, progress_updater)
            
        newDataSources.append(newDataSource.getRootDirectory())
           
        # Get the files that were added
        files_added = progress_updater.getFiles()
        #self.log(Level.INFO, "Fire Module1: ==> " + str(files_added))
            
        for file_added in files_added:
            skcase_data.notifyDataSourceAdded(file_added, device_id)
            #self.log(Level.INFO, "Fire Module1: ==> " + str(file_added))

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Process/Extract VS", " Volume Shadow has been analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

