# This python autopsy module will process DJI_Phantom_Drone_Parser dat files
# from a DJI Phantom Drone.  It calls a modified drop.exe program from 
# https://github.com/unhcfreg/DROP.  The idea for this module came from Dr. Stephen Pearson.
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

# DJI_Phantom_Drone_Parser to process Dat files from the drone.
# October 2018
# 
# Comments 
#   Version 1.0 - Initial version - October 2018
# 

import csv
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
class DJIPhantomDroneIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "DJI_Phantom_Drone"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses DJI Phantom Drone Dat Files"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return DJIPhantomDroneIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class DJIPhantomDroneIngestModule(DataSourceIngestModule):

#    _logger = Logger.getLogger(DJIPhantomDroneIngestModuleFactory.moduleName)

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
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "drop.exe")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("drop.exe was not found in module folder")
        else:        
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Drop")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("Drop executable was not found in module folder")

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.dat")
        numFiles = len(files)
        #self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        moduleDirectory = os.path.join(Case.getCurrentCase().getModuleDirectory(), "DJI_Phantom")
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "DJI_Phantom")
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
            extractedFile = os.path.join(temporaryDirectory, file.getName())
            ContentUtils.writeToFile(file, File(extractedFile))
            self.DJIPhantomDroneFile(moduleDirectory, extractedFile)
            self.DJIPhantomAddExtractedFiles(moduleDirectory, file, skCase)
        
        self.DJIPhantomReportFiles(moduleDirectory)        

        # Clean up
        try:
            shutil.rmtree(temporaryDirectory)
        except:
		    self.log(Level.INFO, "removal of DJI Phantom Data Files Failed " + temporaryDirectory)
  
    
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "DJI_Phantom_Parser", " DJI_Phantom DAT Files Parsed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    def DJIPhantomDroneFile(self,moduleDirectory, extractedFile):

        #drop.exe -o d:\drop-master\output -f --kml d:\drop-master\output d:\drop-master\sample-data\dat-files
        #self.log(Level.INFO, "Running program ==> " + self.pathToExe + " -o " + moduleDirectory + " -f " + " --kml" + " " + moduleDirectory + " " + tempDirectory)
        pipe = Popen([self.pathToExe, "-o", moduleDirectory, "-f", "--kml", moduleDirectory, extractedFile], stdout=PIPE, stderr=PIPE)
        outputFromRun = pipe.communicate()[0]
        #pass           
        
    def DJIPhantomReportFiles(self, moduleDirectory):

        for fileName in os.listdir(moduleDirectory):
            if fileName.endswith(".csv") or fileName.endswith(".kml"): 
                # Add the report to the Case, so it is shown in the tree
                fullFileName = os.path.join(moduleDirectory, fileName)
                self.log(Level.INFO, "FileName ==> " + str(fullFileName))
                Case.getCurrentCase().addReport(fullFileName, fileName, fullFileName)
    

    def DJIPhantomAddExtractedFiles(self, moduleDirectory, file, skCase):
    
        # Columns to get from files:
        #  0 -   messageid      -  TSK_MSG_ID
        #  1 -   offsetTime     - TSK_DJIPHANTOM_OFFSETTIME
        #  4-    Latitude       -  TSK_GEO_LATITUDE
        #  5 -   Longitude      -  TSK_GEO_LONGITUDE
        #  10 -  Height         -  TSK__DJIPHANTOM_HEIGHT
        #  45 -  Flystrate      -  TSK__DJIPHANTOM_FLYSTRATE
        #  46 -  Flystatestr    -  TSK__DJIPHANTOM_FLYSTATESTR
        #  51 -  Current        -  TSK__DJIPHANTOM_CURRENT
        #  54 -  SerialNumber   -  TSK__DJIPHANTOM_BATTERY_SERIALNUMBER
        #  72 -  BatteryBarCode -  TSK__DJIPHANTOM_BATTERY_BARCODE
 
        try:
            self.log(Level.INFO, "Begin Create New Artifacts")
            artId = skCase.addArtifactType("TSK_DJIPHANTOM_DRONE_DATA", "DJI Phantom Drone Data")
        except:		
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artId = skCase.getArtifactTypeID("TSK_DJIPHANTOM_DRONE_DATA")
 
        moduleName = DJIPhantomDroneIngestModuleFactory.moduleName
        fileToParse = self.getCSVFileName(moduleDirectory, file.getName())
        self.log(Level.INFO, "CSV File To Parse ==> " + fileToParse)
        with open (fileToParse) as csvFile:
            csvReader = csv.reader(csvFile, delimiter=',')
            lineCount = 0  
            for row in csvReader:
                if lineCount == 0:
                    lineCount = lineCount + 1
                else:
                    artDJI = file.newArtifact(artId)
                    attributes = ArrayList()
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MSG_ID, moduleName, row[0]))
                    attributes.add(BlackboardAttribute(self.checkAttribute("TSK_DJIPHANTOM_OFFSETTIME", "OffsetTime", skCase), moduleName, row[1]))

                    try:
                        attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LATITUDE, moduleName, float(row[4])))
                    except:
                        attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LATITUDE, moduleName, float(0.0)))
                    try:
                        attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE, moduleName, float(row[5])))
                    except:
                        attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE, moduleName, float(0.0)))
                    
                    attributes.add(BlackboardAttribute(self.checkAttribute("TSK_DJIPHANTOM_HEIGHT", "Height", skCase), moduleName, row[10]))
                    attributes.add(BlackboardAttribute(self.checkAttribute("TSK_DJIPHANTOM_FLYSTRATE", "Flystrate", skCase), moduleName, row[45]))
                    attributes.add(BlackboardAttribute(self.checkAttribute("TSK_DJIPHANTOM_FLYSTATESTR", "Flystatestr", skCase), moduleName, row[46]))
                    attributes.add(BlackboardAttribute(self.checkAttribute("TSK_DJIPHANTOM_Current", "Current", skCase), moduleName, row[51]))
                    attributes.add(BlackboardAttribute(self.checkAttribute("TSK_DJIPHANTOM_BATTERY_SERIALNUMBER", "Battery Serial Number", skCase), moduleName, row[54]))
                    attributes.add(BlackboardAttribute(self.checkAttribute("TSK_DJIPHANTOM_BATTERY_BARCODE", "Battery Bar Code", skCase), moduleName, row[72]))
                
                    artDJI.addAttributes(attributes)
                    # index the artifact for keyword search
                    try:
                        blackboard.indexArtifact(artDJI)
                    except:
                        pass
                        #self.log(Level.INFO, "Index Artifact Failed")


                    lineCount = lineCount + 1
        
        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(moduleName, skCase.getArtifactType("TSK_DJIPHANTOM_DRONE_DATA"), None))

    def getCSVFileName(self, moduleDirectory, fileName):
    
        fileParts = os.path.splitext(fileName)
        csvFileName = fileParts[0] + "-Output.csv"
        return os.path.join(moduleDirectory, csvFileName)
        
    def checkAttribute(self, attributeName, attributeDescription, skCase):

        try:
            attID = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, attributeDescription)
        except:		
            attID = skCase.getAttributeType(attributeName)
        return attID