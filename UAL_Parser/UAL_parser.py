# This python autopsy module will run a version of the Ual program written 
# by Brian Moran against the current.mdb file.  This version that runs creates a summary and
# detail file that will be stored in the ModuleOutput directory
#
# Special Thanks to:
#                 Shanna Daly
#                 Brian Moran
#
# Author Contact: Mark McKinnon [Mark [dot] McKinnon <at> gmail [dot] com]
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

# Ual_Parser module to process current.mdb file.
# March 2021
# 
# Comments 
#   Version 1.0 - Initial version - July 2021
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE
import csv
import datetime
import time

from java.lang import Class
from java.lang import System
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

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class UalParserIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "UAL Parser"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses Current.mdb"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return UalParserIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class UalParserIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(UalParserIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)

    def startUp(self, context):
        self.context = context
        if PlatformUtil.isWindowsOS(): 
           self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_ual.exe")
           if not os.path.exists(self.pathToExe):
               raise IngestModuleException("export_ual.exe was not found in module folder")
        else:
           pass       

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        
        # Get the file manager
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        
        # Find the files in the data source
        files = fileManager.findFiles(dataSource, "current.mdb")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

        # Create Artifact
        try:
            self.log(Level.INFO, "Begin Create New Artifacts")
            artID_Ual = skCase.addArtifactType( "UAL_LOGS", "User Access Logs")
        except:		
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artID_Ual = skCase.getArtifactTypeID("UAL_LOG")

        # Create Custom Artifacts  
        try:
            attID_Ual_Role_Guid = skCase.addArtifactAttributeType("UAL_ROLE_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Role GUID")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, UAL_ROLE_GUID. ==> ")
             attID_Ual_Role_Guid = skCase.getAttributeType("UAL_ROLE_GUID")
        try:
            attID_Ual_Guid_Desc = skCase.addArtifactAttributeType("UAL_GUID_DESC", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "GUID Description")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, UAL_GUID_DESC. ==> ")
             attID_Ual_Guid_Desc = skCase.getAttributeType("UAL_GUID_DESC")
        try:
            attID_Ual_Total_Access = skCase.addArtifactAttributeType("UAL_TOTAL_ACCESS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Total Accesses")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, UAL_Total_Access. ==> ")
             attID_Ual_Total_Access = skCase.getAttributeType("UAL_TOTAL_ACCESS")
        try:
            attID_Ual_Insert_Date = skCase.addArtifactAttributeType("UAL_INSERT_DATE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Insert Date")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, UAL_Insert_Date. ==> ")
             attID_Ual_Insert_Date = skCase.getAttributeType("UAL_INSERT_DATE")
        try:
            attID_Ual_Lastaccess_Date = skCase.addArtifactAttributeType("UAL_LASTACCESS_DATE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last Acess Date")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, UAL_Insert_Date. ==> ")
             attID_Ual_Lastaccess_Date = skCase.getAttributeType("UAL_LASTACCESS_DATE")

		# Create UAL Log directory in temp directory, if it exists then continue on processing		
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "UAL")
        moduleDirectory = os.path.join(Case.getCurrentCase().getModuleDirectory(), "UAL")
        self.log(Level.INFO, "create Directory " + moduleDirectory)
        try:
            os.mkdir(temporaryDirectory)
        except:
            self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)
        try:
            os.mkdir(moduleDirectory)
        except:
            self.log(Level.INFO, "Module directory already exists " + moduleDirectory)
			
        # Write out current.mdb and process it.
        for file in files:
            if "-slack" not in file.getName():
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Processing Path: " + file.getParentPath())
                fileCount += 1

                extractedCurrentFile = os.path.join(temporaryDirectory, file.getName())
                ContentUtils.writeToFile(file, File(extractedCurrentFile))

                outFile = os.path.join(moduleDirectory, str(file.getName()))
                # Command Line to Run is 
                # export_ual -i F:\Windows\System32\Logfiles\SUM\Current.mdb -b e:\output\mark_ual -c
                self.log(Level.INFO, str(self.pathToExe) + " -i " + str(extractedCurrentFile) \
                                + " -b " + str(outFile) + " -c")
                pipe = Popen([self.pathToExe, "-i", extractedCurrentFile, "-b", outFile, "-c"], stdout=PIPE, stderr=PIPE)
                outputFromRun = pipe.communicate()[0]
                self.log(Level.INFO, "Output from Run is ==> " + outputFromRun)

                summaryFile = os.path.join(moduleDirectory, str(file.getName()) + "_SUMMARY.csv")
                attribute_names = ["UAL_ROLE_GUID", "UAL_GUID_DESC", "UAL_TOTAL_ACCESS", "UAL_INSERT_DATE", "UAL_LASTACCESS_DATE", "TSK_IP_ADDRESS", "TSK_HOST", "TSK_USER_NAME"]
                heading_read = False

                with open(summaryFile, 'rU') as csvfile:
                    csvreader = csv.reader(csvfile, delimiter=',', quotechar='|')
                    for row in csvreader:
                        if not heading_read:
                            heading_read = True
                        else:
                            art = file.newArtifact(artID_Ual)
                            attributes = ArrayList()
                            for (data, head) in zip(row, attribute_names): 
                                if head == "UAL_TOTAL_ACCESS":
                                    attributes.add(BlackboardAttribute(skCase.getAttributeType(head), UalParserIngestModuleFactory.moduleName, int(data)))
                                else:
                                    attributes.add(BlackboardAttribute(skCase.getAttributeType(head), UalParserIngestModuleFactory.moduleName, data))
                            art.addAttributes(attributes)

                            try:
                                blackboard.postArtifact(art)
                            except:
                                pass

        # After all processing complete, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Ual Parser", " UAL Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

