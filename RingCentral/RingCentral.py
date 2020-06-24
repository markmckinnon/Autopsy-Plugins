# This python autopsy module will process the RingCentral Data
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
#   Version 1.0 - Initial version - June 2020
# 

import jarray
import inspect
import os
import json
import shutil
from datetime import datetime

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
class RingCentralIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "RingCentral Meeting Chats"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Process RingCentral Meeting Chats"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return RingCentralIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class RingCentralIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(RingCentralIngestModuleFactory.moduleName)

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
        chatFiles = fileManager.findFiles(dataSource, "%.txt", "/Documents/RingCentral/Meetings")
        numFiles = len(chatFiles)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create RingCentral directory in temp directory, if it exists then continue on processing		
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "RingCentral")
        try:
		    os.mkdir(temporaryDirectory)
        except:
            pass
			
        # get and write out chat meeting files
        for file in chatFiles:
            if "-slack" not in file.getName():
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                fileCount += 1

                # Save the file locally. Use file id as name to reduce collisions
                extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
                ContentUtils.writeToFile(file, File(extractedFile))
                self.chatMeetingLogs(extractedFile, file)
                try:
                    os.remove(extractedFile)
                except:
                    self.log(Level.INFO, "Failed to remove file " + extractedFile)


#        try:
#           shutil.rmtree(temporaryDirectory)		
#        except:
#		   self.log(Level.INFO, "removal of temporary directory failed " + temporaryDirectory)
                
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "CentralRing", " CentralRing Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    def chatMeetingLogs(self, chatFile, abstractFile):
    
       moduleName = RingCentralIngestModuleFactory.moduleName
    
       directoryNameList = self.splitDirName(abstractFile.getParentPath())
       chatLogList = self.processChatMessage(chatFile)

       self.log(Level.INFO, "DirectoyNameList ==> " + str(directoryNameList))
       self.log(Level.INFO, "chatLogList ==> " + str(chatLogList))
       
       
       # Attributes
       # TSK_MEETING_DATETIME - Meeting Date/Time
       # TSK_MEETING_ID - Meeting Id
       # TSK_MEETING_CHAT_TIME_SENT - Meeting Chat Time Sent
       # TSK_CHAT_FROM - Chat From
       # TSK_CHAT_TO - Chat To
       # TSK_CHAT_MESSAGE - Chat Message
       try:
           artId = self.createArtifact("TSK_RINGCENTRAL_MEETING", "RingCentral Meeting Chat(s)")
           for chatLogMessage in chatLogList:
              artifact = abstractFile.newArtifact(artId)
              attributes = ArrayList()
              attId = self.createAttribute("TSK_MEETING_DATETIME", "datetime", "Meeting Date/Time")
              attributes.add(BlackboardAttribute(attId, moduleName, directoryNameList[0]))
              self.log(Level.INFO, "FIrst Attribute created")
              attId = self.createAttribute("TSK_MEETING_ID", "string", "Meeting Id")
              attributes.add(BlackboardAttribute(attId, moduleName, directoryNameList[1]))
              self.log(Level.INFO, "Second Attribute created")
              attId = self.createAttribute("TSK_MEETING_CHAT_TIME_SENT", "string", "Meeting Chat Time Sent")
              attributes.add(BlackboardAttribute(attId, moduleName, chatLogMessage[0]))
              attId = self.createAttribute("TSK_CHAT_FROM", "string", "Chat From")
              attributes.add(BlackboardAttribute(attId, moduleName, chatLogMessage[1]))
              if (len(chatLogMessage) > 3):
                  attId = self.createAttribute("TSK_CHAT_TO", "string", "Chat To")
                  attributes.add(BlackboardAttribute(attId, moduleName, chatLogMessage[2]))
                  attId = self.createAttribute("TSK_CHAT_Message", "string", "Chat Message")
                  attributes.add(BlackboardAttribute(attId, moduleName, chatLogMessage[3]))
              else:
                  attId = self.createAttribute("TSK_CHAT_Message", "string", "Chat Message")
                  attributes.add(BlackboardAttribute(attId, moduleName, chatLogMessage[2]))
              
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

    def splitDirName(self, directoryName):
        (dirPath, dirName) = os.path.split(directoryName[:-1])
        # Format of directory name is 2020-06-05 00.13.10 RingCentral Meeting XXXXXXXXXX
        # Assumes XXXXXXXXX does not contain spaces
        meetingInfo = dirName.split(" ")
        dateTuple = (meetingInfo[0], meetingInfo[1])
        meetingDateTimeString = " ".join(dateTuple)
        p = '%Y-%m-%d %H.%M.%S'
        epoch = datetime(1970, 1, 1)
        meetingInfoList = []
        meetingInfoList.append(long((datetime.strptime(meetingDateTimeString, p) - epoch).total_seconds()))
        meetingInfoList.append(meetingInfo[4])
        return meetingInfoList

    def processChatMessage(self, chatMessageFile):
        chatMessageList = []
        with open(chatMessageFile, 'r') as chatFile:
            for chatLine in chatFile:
#            chatLine = chatFile.readline()
#                self.log(Level.INFO, "Chat Line ==> " + chatLine)
                chatLineList = chatLine.split("\t")
                chatTime = chatLineList[0]
                chatFullMessage = chatLineList[1].split(":")
                chatFromTo = chatFullMessage[0]
                chatMessage = chatFullMessage[1]
                if " to " in chatFromTo.lower():
                    chatFromToSplit = chatFromTo.split(" to ")
                    chatMessageList.append((chatTime, chatFromToSplit[0].replace(" From ", ""), chatFromToSplit[1].replace(" to ", ""), chatMessage))
                else:
                    chatMessageList.append((chatTime, chatFromTo.replace(" From ", ""), chatMessage))
        return chatMessageList
            
            
    
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
    
