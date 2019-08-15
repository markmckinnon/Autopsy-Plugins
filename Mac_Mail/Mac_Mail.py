# This python autopsy module will process Mac Mail
# emlx files will be extracted and seperated into headers and body's.  
# The sqlite database that contains the Mail information is then imported into 
# the email section of autopsy as well as account section
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

# Mac_Mail module to process Mac mail.
# May 2018
# 
# Comments 
#   Version 1.0 - Initial version - May 2018
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
class ProcessMacMailIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Mac_Mail"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses Mac Mail Store"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessMacMailIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessMacMailIngestModule(DataSourceIngestModule):

#    _logger = Logger.getLogger(ProcessMacMailIngestModuleFactory.moduleName)

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

        # May need this code if I want to run a program to parse out the actual email files.
        #
        # Get path to executable based on where this script is run from.
        # Assumes executable is in same folder as script
        # Verify it is there before any ingest starts
        # if PlatformUtil.isWindowsOS(): 
            # self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_esedb.exe")
            # if not os.path.exists(self.pathToExe):
                # raise IngestModuleException("export_esedb.exe was not found in module folder")
            # if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_esedb_records.exe")):
                # raise IngestModuleException("export_esedb_records.exe was not found in module folder")
        # else:        
            # self.pathToExe2 = os.path.dirname(os.path.abspath(__file__))
            # self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_esedb")
            # if not os.path.exists(self.pathToExe):
                # raise IngestModuleException("export_esedb was not found in module folder")
            # if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_esedb_records")):
                # raise IngestModuleException("export_esedb_records was not found in module folder")
        pass

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%", "/Users/")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Email directory in temp amd modules directory, if it exists then continue on processing		
        moduleDirectory = os.path.join(Case.getCurrentCase().getModuleDirectory(), "Email")
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "Email")
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
			
        userPaths = []
        # create user paths in Temp dir and then get each user directory to use later.
        for file in files:
            #self.log(Level.INFO, 'Parent Path is ==> ' + file.getParentPath())
            if (file.getParentPath() == '/Users/'):
                try:
                    userPaths.append(file.getName())
                    os.mkdir(os.path.join(temporaryDirectory, file.getName()))
                    self.log(Level.INFO, "Directory created for " + file.getName())
                except:
                    self.log(Level.INFO, "Error creating directory " + os.path.join(temporaryDirectory, file.getName()))
        
        self.log(Level.INFO, "User Paths to get emlx files from ==> " + str(userPaths))

        # Get user Emails and put the in the correct user directories
        for userPath in userPaths:
            self.log(Level.INFO, 'User directory to process' + os.path.join('/Users', userPath).replace('\\','/'))
            files = fileManager.findFiles(dataSource, "%emlx", os.path.join('/Users', userPath).replace('\\','/'))
            numFiles = len(files)
            self.log(Level.INFO, "found " + str(numFiles) + " files")

            # Extract all the emlx files to the correct user directories            
            for file in files:
                if not (file.getName().endswith('-slack')):
                    extractedFile = os.path.join(os.path.join(temporaryDirectory, userPath), file.getName())
                    ContentUtils.writeToFile(file, File(extractedFile))

        # Get the user Envelope Index to see what emails there are
        for userPath in userPaths:
            self.log(Level.INFO, 'User directory to process' + os.path.join('/Users', userPath).replace('\\','/'))
            dbFiles = fileManager.findFiles(dataSource, "Envelope Index%", os.path.join('/Users', userPath).replace('\\','/'))
            numFiles = len(dbFiles)
            self.log(Level.INFO, "found " + str(numFiles) + " files")

            # Extract all the emlx files to the correct user directories            
            for file in dbFiles:
                if (not (file.getName().endswith('-slack')) or not (file.getName().endswith('-shm'))):
                    self.log(Level.INFO, "Writing file ==> " + file.getName())
                    extractedFile = os.path.join(os.path.join(temporaryDirectory, userPath), file.getName())
                    ContentUtils.writeToFile(file, File(extractedFile))
            self.log(Level.INFO, "FIles have been written no lets process them")
            # Process each users Envelope Index SQLite database
            for file in dbFiles:	
               self.log(Level.INFO, "Check file name ==> " + file.getName())
               if (not (file.getName().endswith('-slack')) or not (file.getName().endswith('-wal')) or not (file.getName().endswith('-shm'))):
                   self.log(Level.INFO, "Path to the mail database is ==> " + file.getName())
                   dbFile = os.path.join(os.path.join(temporaryDirectory, userPath), file.getName())
                   try: 
                       Class.forName("org.sqlite.JDBC").newInstance()
                       dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % dbFile)
                   except SQLException as e:
                       #self.log(Level.INFO, "Could not open database file (not SQLite) " + lclDbPath + " (" + e.getMessage() + ")")
                       return IngestModule.ProcessResult.OK
     
                   self.processRecipients(dbConn, skCase, file)
                   self.processEmails(dbConn, skCase, file)

                   # Clean up
                   dbConn.close()
                   #os.remove(lclDbPath)
			
		#Clean up email directory and files
        ### To Do

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Mac Mail Processor", " Mac Mail Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    # May need this code if I want to process each individual emlx file besides using the SQLite db Envelope Index
    def processEsedbFile(self, extractedFile, databaseFile):

        #self.log(Level.INFO, "Running program ==> " + self.pathToExe + " " + extractedFile + databaseFile)
        if PlatformUtil.isWindowsOS():
            pipe = Popen([self.pathToExe, extractedFile, databaseFile], stdout=PIPE, stderr=PIPE)
        else:
            pipe = Popen([self.pathToExe, extractedFile, databaseFile, self.pathToExe2], stdout=PIPE, stderr=PIPE)			
        outputFromRun = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + outputFromRun)               


    def processRecipients(self, dbConn, skCase, file):
    
       # Query the recipients table in the database. 
       try:
           stmt = dbConn.createStatement()
           resultSet = stmt.executeQuery('select distinct address from addresses a, recipients b where a.rowid = b.address_id')
           #self.log(Level.INFO, "query recipient table")
       except SQLException as e:
           self.log(Level.INFO, "Error querying database for recipients/address table (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK


       artIdEmail = skCase.getArtifactTypeID("TSK_ACCOUNT")
       artIdEmailType = skCase.getArtifactType("TSK_ACCOUNT")
         
       # Cycle through each row and create artifacts
       while resultSet.next():
           try: 
               #self.log(Level.INFO, "Result (" + resultSet.getString("recipients") + ")")
               artEmail = file.newArtifact(artIdEmail)
               artEmail.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, "EMAIL"))
               artEmail.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, resultSet.getString("address")))
           except SQLException as e:
               pass
               #self.log(Level.INFO, "Error getting values from recipent table (" + e.getMessage() + ")")

       # Close the database statement
       stmt.close()
               
    def getSenderAccount(self, dbConn, skCase, file, emailAddress):
    
        self._logger.log(Level.INFO, "Result (" + emailAddress + ")")
        senderAccount = emailAddress
        self._logger.log(Level.INFO, senderAccount)
        return skCase.getCommunicationsManager().createAccountFileInstance(Account.Type.EMAIL, senderAccount, ProcessMacMailIngestModuleFactory.moduleName, file)
               
    def getOtherAccounts(self, dbConn, skCase, file, recipientId):
    
       sqlStatement = 'select distinct address from addresses a, recipients b where a.rowid = b.address_id and b.message_id = ' + str(recipientId) + ';'
       otherAccounts = []
       recipientAccounts = []
       # Query the recipients table in the database. 
       try:
           stmt = dbConn.createStatement()
           resultSet = stmt.executeQuery(sqlStatement)
           #self.log(Level.INFO, "query recipient table for from user")
       except SQLException as e:
           #self.log(Level.INFO, "Error querying database for recipient table (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK


       # Should only be one row
       while resultSet.next():
           try: 
               #self.log(Level.INFO, "Result (" + resultSet.getString("Email_Address") + ")")
               individualAccount = skCase.getCommunicationsManager().createAccountFileInstance(Account.Type.EMAIL, resultSet.getString("address"), ProcessMacMailIngestModuleFactory.moduleName, file)
               otherAccounts.append(individualAccount)
               recipientAccounts.append(resultSet.getString("address"))
           except SQLException as e:
               self.log(Level.INFO, "Error getting values from recipent table (" + e.getMessage() + ")")

       # Close the database statement
       stmt.close()
       
       return otherAccounts, ', '.join(recipientAccounts)
       
    def processEmails(self, dbConn, skCase, file):
    
       sqlStatement = "select m.ROWID message_id, a.address Sender, a.address||' ('||a.comment||')' Sender_full, s.subject, m.date_sent, m.date_received, m.date_created, " + \
                      " m.date_last_viewed, m.snippet, mb.url from messages m, subjects s, addresses a, mailboxes mb where m.subject = s.ROWID and m.sender = a.ROWID and m.mailbox = mb.ROWID"

       #sqlStatement = "Select * from mail_messages;"
       
       #self.log(Level.INFO, "SQL Statement ==> ")
       # Query the contacts table in the database and get all columns. 
       try:
           stmt = dbConn.createStatement()
           resultSet = stmt.executeQuery(sqlStatement)
           #self.log(Level.INFO, "query message table")
       except SQLException as e:
           #self.log(Level.INFO, "Error querying database for message table (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK


       artIdEmail = skCase.getArtifactTypeID("TSK_EMAIL_MSG")
       artIdEmailType = skCase.getArtifactType("TSK_EMAIL_MSG")
         
       # Cycle through each row and create artifacts
       while resultSet.next():
           try: 
               senderAccount = self.getSenderAccount(dbConn, skCase, file, resultSet.getString("Sender"))
               otherAccounts, emailRecipients = self.getOtherAccounts(dbConn, skCase, file, resultSet.getString("message_id"))
               self.log(Level.INFO, "Message Id (" + resultSet.getString("message_id") + ")")
               artEmail = file.newArtifact(artIdEmail)
               artEmail.addAttributes(((BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, resultSet.getString("url"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, emailRecipients)), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, resultSet.getString("Sender"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_PLAIN.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, resultSet.getString("snippet"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_RCVD.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, resultSet.getInt("date_received"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, resultSet.getInt("date_Sent"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT.getTypeID(), ProcessMacMailIngestModuleFactory.moduleName, resultSet.getString("subject")))))
               if (not resultSet.getString("url").startswith('feed:')):
                   skCase.getCommunicationsManager().addRelationships(senderAccount, otherAccounts, artEmail,Relationship.Type.MESSAGE, resultSet.getInt("date_sent"));
               

               # index the artifact for keyword search
               try:
                   blackboard.indexArtifact(artEmail)
               except:
                   pass
#                   self._logger.log(Level.SEVERE, "Error indexing artifact " + artEmail.getDisplayName())

           except SQLException as e:
               self.log(Level.INFO, "Error getting values from message table (" + e.getMessage() + ")")

       # Close the database statement
       stmt.close()
       
       # fire event to let the system know new data was added
       #IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ProcessMacMailIngestModuleFactory.moduleName, \
       #                                 artIdEmailType, None))
