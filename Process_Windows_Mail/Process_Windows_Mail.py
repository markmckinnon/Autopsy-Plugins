# This python autopsy module will process the Windows 10 mail store
# The Store.vol file will be extracted and processed into a SQLite database
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

# Process_Windows_Mail module to process Windows mail.
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
class ProcessWinMailIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Windows_Mail"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses The SAM Registry Hive"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessWinMailIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessWinMailIngestModule(DataSourceIngestModule):

#    _logger = Logger.getLogger(ProcessWinMailIngestModuleFactory.moduleName)

#    def log(self, level, msg):
#        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
#        self._logger = Logger.getLogger(self.__class__.__name__)

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
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_esedb.exe")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("export_esedb.exe was not found in module folder")
            if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_esedb_records.exe")):
                raise IngestModuleException("export_esedb_records.exe was not found in module folder")
        else:        
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_esedb")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("export_esedb was not found in module folder")
            if not os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_esedb_records")):
                raise IngestModuleException("export_esedb_records was not found in module folder")

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "store.vol", "UnistoreDB")
        numFiles = len(files)
        #self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
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
            self.processEsedbFile(extractedFile, os.path.join(moduleDirectory, str(file.getId()) + "-" + file.getName() + ".db3"))

        for file in files:	
           # Open the DB using JDBC
           lclDbPath = os.path.join(moduleDirectory, str(file.getId()) + "-" + file.getName() + ".db3")
           #self.log(Level.INFO, "Path to the mail database is ==> " + lclDbPath)
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               #self.log(Level.INFO, "Could not open database file (not SQLite) " + lclDbPath + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
 
           #self.processRecipients(dbConn, skCase, file)
           self.processEmails(dbConn, skCase, file)

           # Clean up
           dbConn.close()
           #os.remove(lclDbPath)
			
		#Clean up EventLog directory and files
        ### To Do

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "WinMail Processor", " Windows Mail Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    def processEsedbFile(self, extractedFile, databaseFile):

        #self.log(Level.INFO, "Running program ==> " + self.pathToExe + " " + extractedFile + databaseFile)
        pipe = Popen([self.pathToExe, extractedFile, databaseFile], stdout=PIPE, stderr=PIPE)
        outputFromRun = pipe.communicate()[0]
        #self.log(Level.INFO, "Output from run is ==> " + outputFromRun)               


    def processRecipients(self, dbConn, skCase, file):
    
       # Query the recipients table in the database. 
       try:
           stmt = dbConn.createStatement()
           resultSet = stmt.executeQuery('select distinct "3003001f" recipients from recipient where length("3003001f")')
           #self.log(Level.INFO, "query recipient table")
       except SQLException as e:
           self.log(Level.INFO, "Error querying database for recipient table (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK


       artIdEmail = skCase.getArtifactTypeID("TSK_ACCOUNT")
       artIdEmailType = skCase.getArtifactType("TSK_ACCOUNT")
         
       # Cycle through each row and create artifacts
       while resultSet.next():
           try: 
               #self.log(Level.INFO, "Result (" + resultSet.getString("recipients") + ")")
               artEmail = file.newArtifact(artIdEmail)
               artEmail.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, "EMAIL"))
               artEmail.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, resultSet.getString("recipients")))
           except SQLException as e:
               pass
               #self.log(Level.INFO, "Error getting values from recipent table (" + e.getMessage() + ")")

       # Close the database statement
       stmt.close()
               
    def getSenderAccount(self, dbConn, skCase, file, InternalId):
    
       sqlStatement = 'select "3003001f" Email_Address from recipient where "20040013" = ' + str(InternalId) + ' and "0c150013" = 0;'
       senderAccount = ""
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
               self._logger.log(Level.INFO, "Result (" + resultSet.getString("Email_Address") + ")")
               senderAccount = resultSet.getString("Email_address")
               self._logger.log(Level.INFO, senderAccount)
               return skCase.getCommunicationsManager().createAccountFileInstance(Account.Type.EMAIL, senderAccount, ProcessWinMailIngestModuleFactory.moduleName, file)
               
           except SQLException as e:
               self.log(Level.INFO, "Error getting values from recipent table (" + e.getMessage() + ")")

       # Close the database statement
       stmt.close()
       #self._logger.log(Level.INFO, "Email Account")
       #self._logger.log(Level.INFO, senderAccount)


       #self.log(Level.INFO, str(senderAccount))
       return skCase.getCommunicationsManager().createAccountFileInstance(Account.Type.EMAIL, senderAccount, ProcessWinMailIngestModuleFactory.moduleName, file)
       
    def getOtherAccounts(self, dbConn, skCase, file, InternalId):
    
       sqlStatement = 'select "3003001f" Email_Address from recipient where "20040013" = ' + str(InternalId) + ' and "0c150013" != 0;'
       otherAccounts = []
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
               individualAccount = skCase.getCommunicationsManager().createAccountFileInstance(Account.Type.EMAIL, resultSet.getString("Email_Address"), ProcessWinMailIngestModuleFactory.moduleName, file)
               otherAccounts.append(individualAccount)
           except SQLException as e:
               self.log(Level.INFO, "Error getting values from recipent table (" + e.getMessage() + ")")

       # Close the database statement
       stmt.close()
       
       return otherAccounts
       
    def processEmails(self, dbConn, skCase, file):
    
       sqlStatement = 'select a."00010003" INTERNAL_ID, a."0c1f001f" TSK_EMAIL_FROM, b."3003001f" TSK_EMAIL_TO, a."003d001f"||a."0037001f" TSK_SUBJECT,'
       sqlStatement = sqlStatement + ' a."3fda001f" TSK_EMAIL_CONTENT_PLAIN, (SUBSTR(a."0e060040",1,11)-11644473600) TSK_DATETIME_SENT, '
       sqlStatement = sqlStatement + ' (substr(a."82a50040",1,11)-11644473600) TSK_DATETIME_RCVD, "\IPM.Root" TSK_PATH '
       sqlStatement = sqlStatement + ' from message a, store b where a."00020003" =  b."00010003"'

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
               senderAccount = self.getSenderAccount(dbConn, skCase, file, resultSet.getString("INTERNAL_ID"))
               otherAccounts = self.getOtherAccounts(dbConn, skCase, file, resultSet.getString("INTERNAL_ID"))
               #self.log(Level.INFO, "Result (" + resultSet.getString("recipients") + ")")
               artEmail = file.newArtifact(artIdEmail)
               artEmail.addAttributes(((BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, resultSet.getString("TSK_PATH"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, resultSet.getString("TSK_EMAIL_TO"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, resultSet.getString("TSK_EMAIL_FROM"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_PLAIN.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, resultSet.getString("TSK_EMAIL_CONTENT_PLAIN"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_RCVD.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, resultSet.getInt("TSK_DATETIME_RCVD"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, resultSet.getInt("TSK_DATETIME_SENT"))), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT.getTypeID(), ProcessWinMailIngestModuleFactory.moduleName, resultSet.getString("TSK_SUBJECT")))))
               skCase.getCommunicationsManager().addRelationships(senderAccount, otherAccounts, artEmail,Relationship.Type.MESSAGE, resultSet.getInt("TSK_DATETIME_SENT"));

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
       #IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ProcessWinMailIngestModuleFactory.moduleName, \
       #                                 artIdEmailType, None))
