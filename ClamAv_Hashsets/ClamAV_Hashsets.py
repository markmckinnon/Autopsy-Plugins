# This python autopsy module will Download the Main.cvd and Daily.cvd files
# from clamav, unpack them using the sigtool and create hash sets in the 
# module output directory that can then be imported into Autopsy Hashsets
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

# ClamAv_Hashsets.py.
# May 2019
# 
# Comments 
#   Version 1.0 - Initial version - May 2019
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE
import csv
import shutil
import sys
import urllib2
from datetime import datetime

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
class ClamAvHsIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "ClamAv Hashset Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Download ClamAv Hashsets Module"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def hasIngestJobSettingsPanel(self):
        return False

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ClamAvHsIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ClamAvHsIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ClamAvHsIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
 
    # Where any setup and configuration is done
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        if PlatformUtil.isWindowsOS():
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigtool.exe")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("EXE was not found in module folder")
        elif PlatformUtil.getOSName() == 'Linux':
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sigtool')
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("Linux Executable was not found in module folder")

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # Get current date and time to append to final hashset file names
        now = datetime.now()
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Create ClamAv directory in temp directory, if it exists then continue on processing		
        temporaryDir = Case.getCurrentCase().getTempDirectory()
        tempDir = os.path.join(temporaryDir, "ClamAv")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
		    os.mkdir(tempDir)
        except:
		    self.log(Level.INFO, "ClamAv Directory already exists " + tempDir)

        moduleDir = Case.getCurrentCase().getModuleDirectory()
        modDir = os.path.join(moduleDir, "ClamAv")
        self.log(Level.INFO, "create Directory " + modDir)
        try:
		    os.mkdir(modDir)
        except:
		    self.log(Level.INFO, "ClamAv Directory already exists " + modDir)
     
        progressBar.progress("Downloading Main.cvd")        
        filedata = urllib2.urlopen('http://database.clamav.net/main.cvd')  
        datatowrite = filedata.read()

        with open(os.path.join(tempDir, "main.cvd"), 'wb') as f:  
            f.write(datatowrite)
    
        progressBar.progress("Downloading Daily.cvd")        
        filedata = urllib2.urlopen('http://database.clamav.net/daily.cvd')  
        datatowrite = filedata.read()

        with open(os.path.join(tempDir, "daily.cvd"), 'wb') as f:  
           f.write(datatowrite)

        progressBar.progress("Unpacking Main.cvd")        
        os.chdir(tempDir)
        self.log(Level.INFO, "Running Command ==> " + self.pathToExe + " " + "--unpack" + " " + os.path.join(tempDir, "main.cvd"))
        pipe = Popen([self.pathToExe, "--unpack", os.path.join(tempDir, "main.cvd")], stdout=PIPE, stderr=PIPE)
        outText = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run ==> " + outText)
    
        progressBar.progress("Unpacking Daily.cvd")        
        self.log(Level.INFO, "Running Command ==> " + self.pathToExe + " " + "--unpack" + " " + os.path.join(tempDir, "daily.cvd"))
        pipe = Popen([self.pathToExe, "--unpack", os.path.join(tempDir, "daily.cvd")], stdout=PIPE, stderr=PIPE)
        outText = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run ==> " + outText)
    
        progressBar.progress("Creating Daily Hashset")        
        with open (os.path.join(tempDir, "daily.hdb"), "r") as hashFile:
            with open (os.path.join(modDir, "ClamAV_Daily_Hashset_" + str(now.strftime("%Y-%m-%d")) + ".txt"), "w") as autopsyHash:
                for line in hashFile:
                    hashLine = line.split(":")
                    autopsyHash.write(hashLine[0] + "\n")
            
        progressBar.progress("Creating Main Hashset")        
        with open (os.path.join(tempDir, "main.hdb"), "r") as hashFile:
            with open (os.path.join(modDir, "ClamAV_Main_Hashset_" + str(now.strftime("%Y-%m-%d")) + ".txt"), "w") as autopsyHash:
                for line in hashFile:
                    hashLine = line.split(":")
                    autopsyHash.write(hashLine[0] + "\n")

		#Clean up recyclebin directory and files
        try:
             shutil.rmtree(tempDir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + tempDir)
 
        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "ClamAV Hashsets", " ClamAV Hashsets have been created " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                

