# This python autopsy module will iOS sysdiagnose data using parsers from 
# cheeky4n6monkey - https://github.com/cheeky4n6monkey/iOS_sysdiagnose_forensic_scripts
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

# iOS sysdiagnose parser for iOS sysdiagnose data.
# May 2018
# 
# Comments 
#   Version 1.0 - Initial version - Oct 2019
# 

import jarray
import inspect
import os
import re
from subprocess import Popen, PIPE
import datetime

from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import ArrayList
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
from org.sleuthkit.autopsy.ingest import ModuleContentEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.datamodel import CommunicationsManager 
from org.sleuthkit.datamodel import Relationship
from org.sleuthkit.datamodel import Account
from org.sleuthkit.datamodel import TskCoreException



# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ProcessiOSSysdiagnoseIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "iOS sysdiagnose"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses iOS sysdiagnose"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessiOSSysdiagnoseIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessiOSSysdiagnoseIngestModule(DataSourceIngestModule):

#    _logger = Logger.getLogger(ProcessiOSSysdiagnoseIngestModuleFactory.moduleName)

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
        self.executablePrograms = self.checkExecutables()

        pass

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Create directorys to store files
        moduleDirectory = os.path.join(Case.getCurrentCase().getModuleDirectory(), "iOS_sysdiagnose")
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "iOS_sysdiagnose")
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


        # Get the current case and a file manager
        self.skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        
        for executableProgram in self.executablePrograms:
            self.log(Level.INFO, "Program to run is ==> " + executableProgram)
            if ('sysdiagnose-sys' in executableProgram):
                extractedFiles = self.extractFile('systemVersion.plist', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_SYSTEMVERSION', "iOS sysdiagnose OS Info", abstractFile)
            elif ('sysdiagnose-networkprefs' in executableProgram):
                extractedFiles = self.extractFile('preferences.plist', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_NETWORKPREFS', "iOS sysdiagnose Hostnames", abstractFile)
            elif ('sysdiagnose-networkinterfaces' in executableProgram):
                extractedFiles = self.extractFile('NetworkInterfaces.plist', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_NETWORKINTERFACES', "iOS sysdiagnose Network Config", abstractFile)
            elif ('sysdiagnose-mobilecontainermanager' in executableProgram):
                extractedFiles = self.extractFile('containermanagerd.log.0', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_MOBILECONTAINERMANAGER', "iOS sysdiagnose Uninstall Info", abstractFile)
            elif ('sysdiagnose-mobilebackup' in executableProgram):
                extractedFiles = self.extractFile('com.apple.MobileBackup.plist', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_MOBILEBACKUP', "iOS sysdiagnose Backup Info", abstractFile)
            elif ('sysdiagnose-mobileactivation' in executableProgram):
                extractedFiles = self.extractFile('mobileactivationd.log', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_MOBILEACTIVATION', "iOS sysdiagnose Activation Startup and Upgrade Info", abstractFile)
            elif ('sysdiagnose-wifi-plist' in executableProgram):
                extractedFiles = self.extractFile('com.apple.wifi.plist', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_WIFI_PLIST', "iOS sysdiagnose WiFi Network Info", abstractFile)
            elif ('sysdiagnose-wifi-icloud' in executableProgram):
                extractedFiles = self.extractFile('ICLOUD_apple.wifid.plist', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_WIFI_NET', "iOS sysdiagnose iCloud WiFi Network Names", abstractFile)
            elif ('sysdiagnose-wifi-net' in executableProgram):
                extractedFiles = self.extractFile('wifi%.log', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + 'net.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + 'net.out'), 'IOS_WIFI_KML', "iOS sysdiagnose WiFi Network Names Info", abstractFile)
            elif ('sysdiagnose-wifi-kml' in executableProgram):
                extractedFiles = self.extractFile('wifi%.log', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + 'kml.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + 'kml.out'), 'IOS_WIFI_KML', "iOS sysdiagnose WiFi KML Network Info", abstractFile)
            elif ('sysdiagnose-uuid2path' in executableProgram):
                extractedFiles = self.extractFile('UUIDToBinaryLocations', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_GUID_PATH', "iOS sysdiagnose GUID and Path Info", abstractFile)
            elif ('sysdiagnose-net-ext-cache' in executableProgram):
                extractedFiles = self.extractFile('com.apple.networkextension.cache.plist', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_NET_EXT_CACHE', "iOS sysdiagnose App Name and GUID Info", abstractFile)
            elif ('sysdiagnose-appconduit' in executableProgram):
                extractedFiles = self.extractFile('AppConduit.log', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_APPCONDUIT', "iOS sysdiagnose Connection Info", abstractFile)
            elif ('sysdiagnose-appupdates' in executableProgram):
                extractedFiles = self.extractFile('AppUpdates.sqlite.db', temporaryDirectory, fileManager, dataSource)
                if (extractedFiles):
                    for abstractFile in extractedFiles:
                            self.executeProgram(executableProgram, os.path.join(temporaryDirectory, str(abstractFile.getId()) + "-" + abstractFile.getName()), os.path.join(moduleDirectory, abstractFile.getName() + '.out'))
                            self.processOutput( os.path.join(moduleDirectory, abstractFile.getName() + '.out'), 'IOS_APPUPDATES', "iOS sysdiagnose Update Info", abstractFile)

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "iOS sysdiagnose", " iOS sysdiagnose Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		               
    def checkExecutables(self):
   
       executableProgramsWindows = ['sysdiagnose-sys.exe','sysdiagnose-networkprefs.exe','sysdiagnose-networkinterfaces.exe', 'sysdiagnose-mobilecontainermanager.exe', \
                                    'sysdiagnose-mobilebackup.exe', 'sysdiagnose-mobileactivation.exe','sysdiagnose-wifi-plist.exe', 'sysdiagnose-wifi-icloud.exe', \
                                    'sysdiagnose-wifi-net.exe.', 'sysdiagnose-wifi-kml.exe', 'sysdiagnose-uuid2path.exe', 'sysdiagnose-net-ext-cache.exe', 'sysdiagnose-appconduit.exe', \
                                    'sysdiagnose-appupdates.exe']
       executableProgramsFound = []   

       if PlatformUtil.isWindowsOS():
           for executable in executableProgramsWindows:
               pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), executable)
               if not os.path.exists(pathToExe):
                   self.log(Level.INFO, "iOS sysdiagnose Windows program " + pathToExe + " not found.")
               else:
                   executableProgramsFound.append(pathToExe)
       else:
           for executable in executableProgramsWindows:
               pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), executable)
               if not os.path.exists(pathToExe):
                   self.log(Level.INFO, "iOS sysdiagnose Linux program " + pathToExe + " not found.")
               else:
                   executableProgramsFound.append(pathToExe)

    
       self.log(Level.INFO, "Programs to execute: " + str(executableProgramsFound))
       return executableProgramsFound
               
    def extractFile(self, fileName, temporaryDirectory, fileManager, dataSource):

        files = fileManager.findFiles(dataSource, fileName)
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")

        fileList = []		
        
        for file in files:
            #self.log(Level.INFO, 'Parent Path is ==> ' + file.getParentPath())
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            try:
                if (not ('PaxHeader' in file.getParentPath())):
                    #self.log(Level.INFO, "Writing file ==> " + file.getName())
                    extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
                    ContentUtils.writeToFile(file, File(extractedFile))
                    fileList.append(file)
            except:
                self.log(Level.INFO, "Error writing File " + os.path.join(temporaryDirectory, file.getName()))
                
        return fileList
    
    def executeProgram(self, executableProgram, extractedFile, outputFile):
    
#        fileKey = extractedFiles.keys()
#        for file in fileKey:
#         self.log(Level.INFO, "Running program ==> " + executableProgram + " -i " + extractedFile)
         if ('sysdiagnose-net-ext-cache' in executableProgram):
             pipe = Popen([executableProgram, "-i", extractedFile, "-v"], stdout=PIPE, stderr=PIPE)
         else:
             pipe = Popen([executableProgram, "-i", extractedFile], stdout=PIPE, stderr=PIPE)
             
         outText = pipe.communicate()[0]
         with open(outputFile, 'w+') as output:
             for line in outText:
                 output.write(line)

    def processOutput(self, inputFile, artifactName, artifactDescription, abstractFile):
    
        dataBlock = False
        attributeList = {}
        with open(inputFile, 'r') as inFile:
            for line in inFile:
#                self.log(Level.INFO, "Length of line is ==> " + str(len(line)))
                if (('Running ' in line) or (len(line) == 2)):
                    continue   
                if ('Found 0 ' in line):
                    continue
                if ('Ignored 0 ' in line):
                    continue
                if ('Exiting ' in line):
                    continue
                if ('GUIDs found' in line):
                    continue
                if ('cache entries retrieved' in line):
                    continue
                # Means that there is a block of data                    
                if ("===" in line):
                    if (dataBlock):
                        dataBlock = True
                        if attributeList:
                            artifactId = self.createArtifact(artifactName, artifactDescription)
#                            self.log(Level.INFO, "Dict list ==> " + str(attributeList))
                            self.processAttributes(attributeList, abstractFile, artifactId)
                        attributeList.clear()
                        continue
                    else:
                        dataBlock = True
                        continue
                if ('IOS_GUID_PATH' in artifactName):
                    attributes = line.split(',')
                    attributeList["GUID"] = attributes[0]
                    attributeList["PATH"] = attributes[1]
                    artifactId = self.createArtifact(artifactName, artifactDescription)
#                    self.log(Level.INFO, "Dict list ==> " + str(attributeList))
                    self.processAttributes(attributeList, abstractFile, artifactId)
                    attributeList.clear()
                elif ('IOS_NET_EXT_CACHE' in artifactName):
                    attributes = line.split(' = ')
                    attributeList["APPNAME"] = attributes[0]
                    attributeList["GUID"] = attributes[1]
                    artifactId = self.createArtifact(artifactName, artifactDescription)
#                    self.log(Level.INFO, "Dict list ==> " + str(attributeList))
                    self.processAttributes(attributeList, abstractFile, artifactId)
                    attributeList.clear()               
                else:
                    attributes = line.split(" = ")
 #                   self.log(Level.INFO, "Attributes ==> " + str(attributes))
                    attributeList[attributes[0]] = attributes[1].rstrip()
        if attributeList:
            artifactId = self.createArtifact(artifactName, artifactDescription)
            self.log(Level.INFO, "Dict list ==> " + str(attributeList))
            self.processAttributes(attributeList, abstractFile, artifactId)
                

    def createArtifact(self, artifactName, artifactDescription):

        try:
            artifactId = self.skCase.addArtifactType( artifactName, artifactDescription)
        except:
           pass
#           self.log(Level.INFO, "Artifact " + artifactName + "Already Exists ")
        
        return self.skCase.getArtifactTypeID(artifactName)    
                
    def processAttributes(self, attributeList, abstractFile, artifactId):
    
        attributes = []
        artifact = abstractFile.newArtifact(artifactId)
        attributeName = attributeList.keys()
        for name in attributeName:
            attributeType = self.checkDataType(attributeList[name])
            self.log(Level.INFO, "Attribute Type for " + name + " is " + attributeType)
            attributeId = self.createAttribute(attributeType, name)
            attributes.append(BlackboardAttribute(attributeId, ProcessiOSSysdiagnoseIngestModuleFactory.moduleName, attributeList[name]))
            
        artifact.addAttributes(attributes)

    def createAttribute(self, attributeType, attributeName):            
          if (attributeType == "STRING"):
              try:
                  attID = self.skCase.addArtifactAttributeType("IOS_" + attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, attributeName)
#                  self.log(Level.INFO, "attribure id for " + "TSK_" + attributeName + " is STRING")
                  return self.skCase.getAttributeType("IOS_" + attributeName)
              except:		
                  return self.skCase.getAttributeType("IOS_" + attributeName)
          elif (attributeType == "LONG"):
              try:
                  attID = self.skCase.addArtifactAttributeType("IOS_" + attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, long(attributeName))
  #                self.log(Level.INFO, "attribure id for " + "TSK_" + attributeName + " is LONG")
                  return self.skCase.getAttributeType("IOS_" + attributeName)
              except:		
                  return self.skCase.getAttributeType("IOS_" + attributeName)
          else:
              try:
                  attID = self.skCase.addArtifactAttributeType("IOS_" + attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, attributeName)
 #                 self.log(Level.INFO, "attribure id for " + "TSK_" + attributeName + " is DATETIME")
                  return self.skCase.getAttributeType("IOS_" + attributeName)
              except:		
                  return self.skCase.getAttributeType("IOS_" + attributeName)


    def checkDataType(self, attributeData):

#       self.log(Level.INFO, "Data is ==> " + str(attributeData))
       if (isinstance(attributeData, datetime.datetime)):
           return "DATETIME"
       elif (isinstance(attributeData, float)):
           return "FLOAT"
       else:
           return "STRING"
