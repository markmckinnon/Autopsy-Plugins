# This python autopsy module will Extract the system and sam registry hive.
#  It will parse out the BAM key and attribute users to it then bring it
#  into Autopsy
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

# bam_key.py.
# April 2019
# 
# Comments 
#   Version 1.0 - Initial version - April 2019
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE
import csv
import shutil

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
class BamKeyIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Bam Key Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Extract BAM Registry Information"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def hasIngestJobSettingsPanel(self):
        return False

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return BamKeyIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class BamKeyIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(BamKeyIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
 
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        if PlatformUtil.isWindowsOS():
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bam_key.exe")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("EXE was not found in module folder")
        elif PlatformUtil.getOSName() == 'Linux':
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bam_key')
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("Linux Executable was not found in module folder")

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        filesToExtract = ("SAM", "SAM.LOG1", "SAM.LOG2", "SYSTEM", "SYSTEM.LOG1", "SYSTEM.LOG2")
        
        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Create BAM directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        temp_dir = os.path.join(Temp_Dir, "bam")
        self.log(Level.INFO, "create Directory " + temp_dir)
        try:
		    os.mkdir(temp_dir)
        except:
		    self.log(Level.INFO, "bam Directory already exists " + temp_dir)

        systemAbsFile = []
        for fileName in filesToExtract:
            files = fileManager.findFiles(dataSource, fileName, "Windows/System32/Config")
            numFiles = len(files)
            #self.log(Level.INFO, "Number of SAM Files found ==> " + str(numFiles))
            
            for file in files:
            
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                
                #self.log(Level.INFO, "Parent Path ==> " + str(file.getParentPath()))
                if file.getParentPath() == '/Windows/System32/config/':    
                    # Save the DB locally in the temp folder. use file id as name to reduce collisions
                    lclDbPath = os.path.join(temp_dir, file.getName())
                    ContentUtils.writeToFile(file, File(lclDbPath))
                    if file.getName() == 'SYSTEM':
                       systemAbsFile = file
                else:
                    self.log(Level.INFO, "Skipping File " + file.getName() + " In Path " + file.getParentPath())

        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on " + self.pathToExe + temp_dir + "  " + os.path.join(temp_dir, 'bam.csv'))
        pipe = Popen([self.pathToExe, temp_dir, os.path.join(temp_dir, "bam.csv")], stdout=PIPE, stderr=PIPE)
        outText = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + outText) 
                    
        # Setup Artifact
        try:
            self.log(Level.INFO, "Begin Create New Artifacts")
            artID_ls = skCase.addArtifactType( "TSK_BAM_KEY", "BAM Registry Key")
        except:		
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            
        artifactName = "TSK_BAM_KEY"
        artIdCsv = skCase.getArtifactTypeID(artifactName)

        # Read CSV File and Import into Autopsy
        headingRead = False
        attributeNames = []
        with open(os.path.join(temp_dir, 'bam.csv'), 'rU') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=',', quotechar='|')
            for row in csvreader:
                if not headingRead:
                    for colName in row:
                        attributeNames.append(colName.upper().strip())
                    headingRead = True
                else:
                    art = systemAbsFile.newArtifact(artIdCsv)
                    for (data, head) in zip(row, attributeNames):
                        try:
                            art.addAttribute(BlackboardAttribute(skCase.getAttributeType(head), BamKeyIngestModuleFactory.moduleName, data))
                        except:
                            art.addAttribute(BlackboardAttribute(skCase.getAttributeType(head), BamKeyIngestModuleFactory.moduleName, int(data)))
        
		#Clean up prefetch directory and files
        try:
             shutil.rmtree(temp_dir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + temp_dir)
 
        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "BamKey", " BamKey Files Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                



