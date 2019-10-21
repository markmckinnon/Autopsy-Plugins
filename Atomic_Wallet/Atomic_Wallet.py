# This python autopsy module will process the Atomic Wallet Crypto Currency App
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

# Atomic_Wallet module to process Information from the atomic application.
# April 2019
# 
# Comments 
#   Version 1.0 - Initial version - April 2019
#   Version 1.1 - Fix Comments - Oct 2019
# 

import jarray
import inspect
import os
from time import strptime, mktime 
import json
import shutil

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
class AttomicWalletIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Atomic_Wallet"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Process Atomic Wallet App"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return AttomicWalletIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class AttomicWalletIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(AttomicWalletIngestModuleFactory.moduleName)

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
        pass
        
    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        connectionFiles = fileManager.findFiles(dataSource, "Connection.log%", ".atomic")
        numFiles = len(connectionFiles)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Atomic Wallet directory in temp directory, if it exists then continue on processing		
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "Atomic_Wallet")
        try:
		    os.mkdir(temporaryDirectory)
        except:
            pass
			
        # get and process connections
        for file in connectionFiles:
            if "-slack" not in file.getName():
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                fileCount += 1

                # Save the file locally. Use file id as name to reduce collisions
                extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
                ContentUtils.writeToFile(file, File(extractedFile))
                self.processConnectionLogs(extractedFile, file)
                try:
                    os.remove(extractedFile)
                except:
                    self.log(Level.INFO, "Failed to remove file " + extractedFile)

            else:
                extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
                try:
                    os.remove(extractedFile)
                except:
                    self.log(Level.INFO, "Failed to remove file " + extractedFile)


        # Get and process history file            
        historyFiles = fileManager.findFiles(dataSource, "history.json", ".atomic")
        numFiles = len(historyFiles)

        for file in historyFiles:	
            if "-slack" not in file.getName():
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                #self.log(Level.INFO, "Processing file: " + file.getName())
                fileCount += 1

                # Save the file locally. Use file id as name to reduce collisions
                extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
                ContentUtils.writeToFile(file, File(extractedFile))
                self.processHistory(extractedFile, file)
                try:
                    os.remove(extractedFile)
                except:
                    self.log(Level.INFO, "Failed to remove file " + extractedFile)
            else:
                extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
                try:
                    os.remove(extractedFile)
                except:
                    self.log(Level.INFO, "Failed to remove file " + extractedFile)

        try:
           shutil.rmtree(temporaryDirectory)		
        except:
		   self.log(Level.INFO, "removal of temporary directory failed " + temporaryDirectory)
                
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Atomic Wallet", " Atomic Wallet Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    def processConnectionLogs(self, logFile, abstractFile):
    
       moduleName = AttomicWalletIngestModuleFactory.moduleName
    
       connectTimes = []
       disconnectTimes = []
       with open(logFile) as file:
           for logLine in file:
               if "connected" in logLine:
                   logLineList = logLine.split(" ")
                   connectTimes.append(int(self.getDateTime(logLineList[0], logLineList[1])))
               elif "Disconnect" in logLine:
                   logLineList = logLine.split(" ")
                   disconnectTimes.append(int(self.getDateTime(logLineList[0], logLineList[1])))
               else:
                   pass
       try:
           artId = self.createArtifact("TSK_ATOMIC_WALLET_APP_TIMES", "Atomic Wallet Connect/Disconnect Times")
           for connTime in connectTimes:
               artifact = abstractFile.newArtifact(artId)
               attributes = ArrayList()
               attId = self.createAttribute("TSK_ATOMIC_WALLET_CONNECTION_TYPE", "string", "Atomic Wallet Connection Type")
               attributes.add(BlackboardAttribute(attId, moduleName, "Connect"))
               attId = self.createAttribute("TSK_ATOMIC_WALLET_TIME", "datetime", "Atomic Wallet Time")
               attributes.add(BlackboardAttribute(attId, moduleName, connTime))
               try:
                   artifact.addAttributes(attributes)
               except:
                   self.log(Level.INFO, "Error adding attribute to artifact")
               try:
                   self.indexArtifact(artifact)
               except:
                   self.log(Level.INFO, "Error indexing artifact")
           for disTime in disconnectTimes:
               artifact = abstractFile.newArtifact(artId)
               attributes = ArrayList()
               attId = self.createAttribute("TSK_ATOMIC_WALLET_CONNECTION_TYPE", "string", "Atomic Wallet Connection Type")
               attributes.add(BlackboardAttribute(attId, moduleName, "Disconnect"))
               attId = self.createAttribute("TSK_ATOMIC_WALLET_TIME", "datetime", "Atomic Wallet Time")
               attributes.add(BlackboardAttribute(attId, moduleName, disTime))
               try:
                   artifact.addAttributes(attributes)
               except:
                   self.log(Level.INFO, "Error adding attribute to artifact")
               try:
                   self.indexArtifact(artifact)
               except:
                   self.log(Level.INFO, "Error indexing artifact")
       except:
           self.log(Level.INFO, "Error adding attribute")

    def processHistory(self, historyFile, abstractFile):

       moduleName = AttomicWalletIngestModuleFactory.moduleName

       histTrans = []
       with open (historyFile) as file:
           for historyLine in file:
               jsonData = json.loads(historyLine)
               for transaction in jsonData:
                  transactionDict = {}
                  for trans in transaction:
                      if isinstance(transaction[trans],dict):
                          header = transaction[trans]
                          newHeader = header.keys()
                          for head in header:
                              transactionDict["transaction_" + trans + "_" + head] = header[head]
                      else:
                          if 'time' in trans:
                             transactionDict["transaction_" + str(trans) + "_UTC"] = transaction[trans]
                          else:
                             transactionDict["transaction_" + str(trans)] = transaction[trans]

                  histTrans.append(transactionDict)
       #self.log(Level.INFO, str(histTrans))
       try:
           artId = self.createArtifact("TSK_ATOMIC_WALLET_TRANS_HIST", "Atomic Wallet Transaction History")
           for history in histTrans:
               hKeys = history.keys()
               attributes = ArrayList()
               artifact = abstractFile.newArtifact(artId)
               for key in hKeys:
                   value = history[key]
                   title = str(key).replace("_"," ").title()
                   attributeName = "TSK_" + str(key).upper()
                   if type(value) == int:
                       if "UTC" in attributeName:
                           attId = self.createAttribute(attributeName, "datetime", title)
                           attributes.add(BlackboardAttribute(attId, moduleName, value))
                       else:
                           attId = self.createAttribute(attributeName, "string", title)
                           attributes.add(BlackboardAttribute(attId, moduleName, str(value)))
                   elif type(value) == dict:
                       pass
                   else:
                       attId = self.createAttribute(attributeName, "string", title)
                       attributes.add(BlackboardAttribute(attId, moduleName, str(value)))
               try:
                   artifact.addAttributes(attributes)
               except:
                   self.log(Level.INFO, "Error adding attribute to artifact")
               try:
                   self.indexArtifact(artifact)
               except:
                   self.log(Level.INFO, "Error indexing artifact")
       except:
           self.log(Level.INFO, "Error adding attribute")
               
    def getDateTime(self, date, time):
    
        dateString = date + " " + time
        timeStamp = strptime(dateString, '%Y-%m-%d %H:%M:%S.%f')
        return mktime(timeStamp)
    
    def createAttribute(self, attributeName, attributeType, attributeDescription):
        
        skCase = Case.getCurrentCase().getSleuthkitCase()
        
        try:
            if "string" == attributeType:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, attributeDescription)
                return skCase.getAttributeType(attributeName)
            elif "datetime" == attributeType:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, attributeDescription)
                return skCase.getAttributeType(attributeName)
            elif "integer" == attributeType:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, attributeDescription)
                return skCase.getAttributeType(attributeName)
            elif "long" == attributeType:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, attributeDescription)
                return skCase.getAttributeType(attributeName)
            elif "double" == attributeType:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, attributeDescription)
                return skCase.getAttributeType(attributeName)
            elif "byte" == attributeType:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE, attributeDescription)
                return skCase.getAttributeType(attributeName)
            else:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, attributeDescription)
                return skCase.getAttributeType(attributeName)
        except:		
            self.log(Level.INFO, "Attributes Creation Error  ==> " + str(attributeName) + " <<>> " + str(attributeType) + " <<>> " + str(attributeDescription))
            return skCase.getAttributeType(attributeName)

    def createArtifact(self, artifactName, artifactDescription):
    
        skCase = Case.getCurrentCase().getSleuthkitCase();
                
        try:
             artId = skCase.addArtifactType(artifactName, artifactDescription)
             return skCase.getArtifactTypeID(artifactName)
        except:		
             #self.log(Level.INFO, "Artifacts Creation Error for artifact ==> " + str(artifactName) + " <<>> " + artifactDescription)
             return skCase.getArtifactTypeID(artifactName)

    def indexArtifact(self, artifact):
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        try:
            blackboard.indexArtifact(artChat)
        except:
            pass
    
