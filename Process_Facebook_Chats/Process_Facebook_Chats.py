# This python autopsy module will process the Windows Facebook Chat app
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

# Process_Facebook_Chat module to process Facebook Chats.
# April 2018
# 
# Comments 
#   Version 1.0 - Initial version - April 2018
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
class ProcessFacebookChatIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Facebook_Chat"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses Facebook Chats"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessFacebookChatIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessFacebookChatIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ProcessFacebookChatIngestModuleFactory.moduleName)

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
        if PlatformUtil.isWindowsOS(): 
           self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fb_chat.exe")
           if not os.path.exists(self.pathToExe):
               raise IngestModuleException("fb_chat.exe was not found in module folder")
        else:        
           self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fb_chat")
           if not os.path.exists(self.pathToExe):
               raise IngestModuleException("fb_chat was not found in module folder")

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "fbsyncstore.db")
        numFiles = len(files)
        #self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "FB_Chat")
        #self.log(Level.INFO, "create Directory " + moduleDirectory)
        try:
		    os.mkdir(temporaryDirectory)
        except:
            pass
            #self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)
			
        # Write out each users store.vol file and process it.
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the file locally. Use file id as name to reduce collisions
            extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
            ContentUtils.writeToFile(file, File(extractedFile))
            #os.remove(extractedFile)

        # Get and process chats            
        files = fileManager.findFiles(dataSource, "orca2.db")
        numFiles = len(files)
        #self.log(Level.INFO, "found " + str(numFiles) + " files")

        databaseFile = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autopsy_Chat.db3")
        for file in files:	
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the file locally. Use file id as name to reduce collisions
            extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
            ContentUtils.writeToFile(file, File(extractedFile))
            self.log(Level.INFO, str(self.pathToExe) + " " + str(extractedFile) + " " + str(temporaryDirectory) + " " + str(databaseFile))
            pipe = Popen([self.pathToExe, extractedFile, temporaryDirectory, databaseFile], stdout=PIPE, stderr=PIPE)
            outputFromRun = pipe.communicate()[0]

            self.processFbChat(databaseFile)
            self.processChats(skCase, file)
            #os.remove(extractedFile)
 
			

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Facebook Chat", " Facebook Chat Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    def getFBOwner(self, dbConn):
    
       try:
           stmt = dbConn.createStatement()
           resultSet = stmt.executeQuery("select user_name from Autopsy_fbowner;")
           self.log(Level.INFO, "query Autopsy_fbowner table")
       except SQLException as e:
           self.log(Level.INFO, "Error querying database for fbowner table (" + e.getMessage() + ") ")
           return IngestModule.ProcessResult.OK


       # Cycle through each row and find owner
       while resultSet.next():
           try: 
                self.fbOwnerId = resultSet.getString("user_name")
           except SQLException as e:
               #pass
               self.log(Level.INFO, "Error getting values from fbowner table (" + e.getMessage() + ")")

       # Close the database statement
       try:
           stmt.close()
       except:
           pass

    def processFbChat(self, extractedFile):
    
       try: 
           Class.forName("org.sqlite.JDBC").newInstance()
           dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % extractedFile)
       except SQLException as e:
           self.log(Level.INFO, "Could not open database file (not SQLite) " + extractedFile + " (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK

           
       self.getFBOwner(dbConn)
       
       # Query the autopsy_chat table in the database. 
       try:
           stmt = dbConn.createStatement()
           resultSet = stmt.executeQuery("select message_id, user_id, sender_id, message||' '||attachment_description||' '||attachment_href message, " + \
                                         " sender_name, receiver_name, dttm from autopsy_chat;")
           self.log(Level.INFO, "query Autopsy_chat table")
       except SQLException as e:
           self.log(Level.INFO, "Error querying database for messages table (" + e.getMessage() + ") extractedFile ==> " + extractedFile)
           return IngestModule.ProcessResult.OK


       # Cycle through each row and create FB Chat List
       # message_id, user_id, sender_id, Message||' '||attachment_description||' '||attachment_href, sender_name, receiver_name, Recvd Dttm
       while resultSet.next():
           try: 
                chatMessage = []
                chatMessage.append(resultSet.getString("message_Id"))
                chatMessage.append(resultSet.getInt("user_Id"))
                chatMessage.append(resultSet.getInt("sender_Id"))
                chatMessage.append(resultSet.getString("message"))
                chatMessage.append(resultSet.getString("sender_name"))
                chatMessage.append(resultSet.getString("receiver_name"))
                chatMessage.append(resultSet.getInt("dttm"))
#                chatMessage.append(cMessage[0])
                self.chatMessages.append(chatMessage)
                self._logger.log(Level.INFO, "Chat Message ==> " + str(chatMessage))

           except SQLException as e:
               #pass
               self.log(Level.INFO, "Error getting values from recipent table (" + e.getMessage() + ")")

       # Close the database statement
       try:
           stmt.close()
           dbConn.close()
       except:
           pass

    def getAccountInstance(self, skCase, accountName, file):
    
        return skCase.getCommunicationsManager().createAccountFileInstance(Account.Type.FACEBOOK, accountName, ProcessFacebookChatIngestModuleFactory.moduleName, file)
       
      
    def processChats(self, skCase, file):
    
       artIdChat = skCase.getArtifactTypeID("TSK_MESSAGE")
       artIdChatType = skCase.getArtifactType("TSK_MESSAGE")
         
       moduleName = ProcessFacebookChatIngestModuleFactory.moduleName
       #chatMessage list
       # message_id, user_id, sender_id, Message, attachment_description, attachment_href, sender_name, receiver_name, Recvd Dttm
       # message_id, user_id, sender_id, Message||' '||attachment_description||' '||attachment_href, sender_name, receiver_name, Recvd Dttm
       # Cycle through each row and create artifacts
       for chatMessage in self.chatMessages:
           try: 
               senderAccount = self.getAccountInstance(skCase, chatMessage[4], file)
               receiverAccount = []
               receiverAccount.append(self.getAccountInstance(skCase, chatMessage[5], file))
               textMessage = chatMessage[3]
               #self.log(Level.INFO, "Result (" + resultSet.getString("recipients") + ")")
               artChat = file.newArtifact(artIdChat)
               attributes = ArrayList()
               if chatMessage[4] <> self.fbOwnerId:
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION, moduleName, "Incoming"))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, moduleName, chatMessage[4]))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, moduleName, chatMessage[5]))
               else:
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION, moduleName, "Outgoing"))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, moduleName, chatMessage[5]))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, moduleName, chatMessage[4]))
                
               attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MSG_ID.getTypeID(), moduleName, chatMessage[0]))
               #attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO.getTypeID(), moduleName, chatMessage[4]))
               #attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM.getTypeID(), moduleName, chatMessage[5]))
               attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT.getTypeID(), moduleName, textMessage))
               attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), moduleName, chatMessage[6]))
               attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE, moduleName, "SMS Message"))
               
               artChat.addAttributes(attributes)
               skCase.getCommunicationsManager().addRelationships(senderAccount, receiverAccount, artChat,Relationship.Type.MESSAGE, chatMessage[6]);

               # index the artifact for keyword search
               try:
                   blackboard.indexArtifact(artChat)
               except:
                   pass
#                   self._logger.log(Level.SEVERE, "Error indexing artifact " + artChat.getDisplayName())

           except SQLException as e:
               self.log(Level.INFO, "Error getting values from message table (" + e.getMessage() + ")")
 