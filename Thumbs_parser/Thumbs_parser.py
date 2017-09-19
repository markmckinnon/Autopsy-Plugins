# This python autopsy module will export all the thumbs.db files im the image and
# then run the thumbs_viewer program, written by Eric Kutcher (https://github.com/thumbsviewer/thumbsviewer), 
# against them and export the embedded files
# to the ModuleOutput directory so that the files can then be added back into 
# Autopsy.
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

# Thumbs_parser.py.
# July 2017
# 
# Comments 
#   Version 1.0 - Initial version - July 2017
#   Version 1.1 - Added code so if run again it will not readd any thumbs that already exist
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


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ThumbsIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Thumbs.db Parser Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Extract Content Fron Thumbs.db Files"
    
    def getModuleVersionNumber(self):
        return "1.1"
    
    def hasIngestJobSettingsPanel(self):
        return False

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ThumbsIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ThumbsIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ThumbsIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
 
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        #Show parameters that are passed in
        self.path_to_exe_thumbs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "thumbs_viewer.exe")
        if not os.path.exists(self.path_to_exe_thumbs):
            raise IngestModuleException("Thumbs_viewer File to Run/execute does not exist.")

     
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        thumb_files = fileManager.findFiles(dataSource, "thumbs.db", "")
        numFiles = len(thumb_files)
        self.log(Level.INFO, "Number of Thumbs.db files found ==> " + str(numFiles))
        
		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getModulesOutputDirAbsPath()
        tmp_dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Thumbs.db")
        except:
		    self.log(Level.INFO, "Thumbs.db Directory already exists " + Temp_Dir)

        for thumb_file in thumb_files:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + thumb_file.getName())
            #fileCount += 1
    
            out_dir = os.path.join(Temp_Dir + "\Thumbs.db", str(thumb_file.getId()) + "-" + thumb_file.getName())
            try:
		        os.mkdir(Temp_Dir + "\Thumbs.db\\" + str(thumb_file.getId()) + "-" + thumb_file.getName())
            except:
		        self.log(Level.INFO, str(thumb_file.getId()) + "-" + thumb_file.getName() + " Directory already exists " + Temp_Dir)


            # Save the thumbs.DB locally in the ModuleOutput folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(tmp_dir, str(thumb_file.getId()) + "-" + thumb_file.getName())
            ContentUtils.writeToFile(thumb_file, File(lclDbPath))

            # Run thumbs_viewer against the selected Database
            self.log(Level.INFO, "Running prog ==> " + self.path_to_exe_thumbs + " -O " + out_dir + " " + lclDbPath)
            pipe = Popen([self.path_to_exe_thumbs, "-O", out_dir, lclDbPath], stdout=PIPE, stderr=PIPE)
            out_text = pipe.communicate()[0]
            self.log(Level.INFO, "Output from run is ==> " + out_text)               
        
            # Get the parent abstract file Information
            abstract_file_info = skCase.getAbstractFileById(thumb_file.getId())
            #self.log(Level.INFO, "Abstract File Info ==> " + str(abstract_file_info))
        
            files = next(os.walk(out_dir))[2]
            for file in files:
                self.log(Level.INFO, " File Name is ==> " + file)
                
                dev_file = os.path.join(out_dir, file)
                local_file = os.path.join("ModuleOutput\\thumbs.db\\" + str(thumb_file.getId()) + "-" + thumb_file.getName(), file)
                self.log(Level.INFO, " Dev File Name is ==> " + dev_file)
                self.log(Level.INFO, " Local File Name is ==> " + local_file)
                
                if not(self.check_dervived_existance(dataSource, file, abstract_file_info)):
                
                    # Add dervived file
                    # Parameters Are:
                    #    File Name, Local Path, size, ctime, crtime, atime, mtime, isFile, Parent File, rederive Details, Tool Name, 
                    #     Tool Version, Other Details, Encoding Type
                    dervived_file = skCase.addDerivedFile(file, local_file, os.path.getsize(dev_file), + \
                                             0, 0, 0, 0, True, abstract_file_info, "", "thumb_viewer", "1.0.2.6", "", TskData.EncodingType.NONE)
                    #self.log(Level.INFO, "Derived File ==> " + str(dervived_file))
                else:
                    pass                
        
        
            try:
              os.remove(lclDbPath)
            except:
              self.log(Level.INFO, "removal of thumbs.db file " + lclDbPath + " failed " )

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Thumbs.db", " Thumbs.db Files Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
         

    def check_dervived_existance(self, dataSource, file_name, parent_file_abstract):

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        dervived_file = fileManager.findFiles(dataSource, file_name, parent_file_abstract)
        numFiles = len(dervived_file)
    
        if numFiles == 0:
            return True
        else:
            return False


