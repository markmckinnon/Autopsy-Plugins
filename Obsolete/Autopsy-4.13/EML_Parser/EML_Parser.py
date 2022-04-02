# This python autopsy module will process EML Files
# eml files will be extracted and seperated into headers and body's and attachments.  
# The information is then imported into The email section of autopsy as well as account section
#
# emlParser code taken and modified from https://stackoverflow.com/questions/31392361/how-to-read-eml-file-in-python
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

# EML Parser module to process EML Files.
# May 2018
# 
# Comments 
#   Version 1.0 - Initial version - May 2018
# 

from email import message_from_file
from email.utils import parsedate_tz, mktime_tz
import jarray
import inspect
import os
import re


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
class ProcessEmlEmailIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "EML Parser"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses EML Mail Messages"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessEmlEmailIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessEmlEmailIngestModule(DataSourceIngestModule):

#    _logger = Logger.getLogger(ProcessEmlEmailIngestModuleFactory.moduleName)

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
        pass

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.eml")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Email directory in temp amd modules directory, if it exists then continue on processing		
        moduleDirectory = os.path.join(Case.getCurrentCase().getModuleDirectory(), "Email-Eml")
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "Email-Eml")
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
			
        for file in files:
            #self.log(Level.INFO, 'Parent Path is ==> ' + file.getParentPath())
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            try:
                if (not (file.getName().endswith('-slack'))):
                    #self.log(Level.INFO, "Writing file ==> " + file.getName())
                    extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
                    ContentUtils.writeToFile(file, File(extractedFile))
            except:
                self.log(Level.INFO, "Error writing File " + os.path.join(temporaryDirectory, file.getName()))
            
        if self.context.isJobCancelled():
            return IngestModule.ProcessResult.OK
        eml = emlParser(temporaryDirectory, moduleDirectory)
        eml.processEmls()
        emlList = eml.getEmlList()

        if self.context.isJobCancelled():
            return IngestModule.ProcessResult.OK
        
        # Get the user Envelope Index to see what emails there are
        for file in files:	
           #self.log(Level.INFO, "Check file name ==> " + file.getName())
           if (not (file.getName().endswith('-slack'))):
               if self.context.isJobCancelled():
                   return IngestModule.ProcessResult.OK
               self.processEmails(skCase, file, emlList[str(file.getId()) + "-" + file.getName()], dataSource)

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Mac Mail Processor", " Mac Mail Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		               
    def getSenderAccount(self, skCase, file, emailAddress):
    
        #self._logger.log(Level.INFO, "Result (" + emailAddress + ")")
        senderAccount = emailAddress
        #self._logger.log(Level.INFO, senderAccount)
        return skCase.getCommunicationsManager().createAccountFileInstance(Account.Type.EMAIL, senderAccount, ProcessEmlEmailIngestModuleFactory.moduleName, file)
               
    def getOtherAccounts(self, skCase, file, recipientTo, receipientCc):
    
       otherAccounts = []
       recipientAccounts = []

       listToProcess = []
       
       if type(recipientTo) == list:
          for to in recipientTo:
              listToProcess.append(to)
       else:
          listToProcess.append(recipientTo)
          
       if type(receipientCc) == list:
          for cc in receipientCc:
              listToProcess.append(cc)
       else:
          if receipientCc != '':
              listToProcess.append(receipientCc)
       
       for mailReceipient in listToProcess:
           #self.log(Level.INFO, "Result (" + resultSet.getString("Email_Address") + ")")
           individualAccount = skCase.getCommunicationsManager().createAccountFileInstance(Account.Type.EMAIL, mailReceipient, ProcessEmlEmailIngestModuleFactory.moduleName, file)
           otherAccounts.append(individualAccount)
           recipientAccounts.append(mailReceipient)
       
       return otherAccounts, ', '.join(recipientAccounts)
       
    def processEmails(self, skCase, file, emailInfo, dataSource):
  
#       self.log(Level.INFO, "Processing File number " + str(file.getId()))
  
       artIdEmail = skCase.getArtifactTypeID("TSK_EMAIL_MSG")
       artIdEmailType = skCase.getArtifactType("TSK_EMAIL_MSG")
         
       # Cycle through each row and create artifacts
       try: 
           emailDate = self.getDateTime(emailInfo['date'], str(file.getId()) + "-" + file.getName())
           if emailDate != 0:
               senderAccount = self.getSenderAccount(skCase, file, emailInfo['from'])
               otherAccounts, emailRecipients = self.getOtherAccounts(skCase, file, emailInfo['to'], emailInfo['cc'])
               emailDate = self.getDateTime(emailInfo['date'], str(file.getId()) + "-" + file.getName())
               #self.log(Level.INFO, "Message Id (" + emailInfo['subject'] + " ) ")
               #self.log(Level.INFO, "file ==> " + str(file))
               artEmail = file.newArtifact(artIdEmail)
               if len(emailInfo['attachments']) > 0:
                  self.addAttachments(emailInfo['attachments'], skCase, dataSource, artEmail)
               attribute = ArrayList()
               attribute.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), ProcessEmlEmailIngestModuleFactory.moduleName, file.getParentPath()))
               attribute.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO.getTypeID(), ProcessEmlEmailIngestModuleFactory.moduleName, emailRecipients))
               attribute.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM.getTypeID(), ProcessEmlEmailIngestModuleFactory.moduleName, emailInfo['from']))
               attribute.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_PLAIN.getTypeID(), ProcessEmlEmailIngestModuleFactory.moduleName, emailInfo['text']))
               attribute.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT.getTypeID(), ProcessEmlEmailIngestModuleFactory.moduleName, emailDate))
               attribute.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT.getTypeID(), ProcessEmlEmailIngestModuleFactory.moduleName, emailInfo['subject']))
               artEmail.addAttributes(attribute)
               skCase.getCommunicationsManager().addRelationships(senderAccount, otherAccounts, artEmail,Relationship.Type.MESSAGE, emailDate)
       except TskCoreException as e:
           self.log(Level.INFO, "Error in adding email " + emailInfo['subject'])
           self.log(Level.INFO, "File name is ==> " +  str(file.getId()) + "-" + file.getName())
           self.log(Level.INFO, "TSK Core Exception - need to look at this file")
                  

       # index the artifact for keyword search
       try:
           blackboard.indexArtifact(artEmail)
       except:
           pass
    

    def addAttachments(self, attachments, skCase, dataSource, bbArtifact):

        self.log(Level.INFO, "Attachments to add ==> " + str(attachments))
        for attachment in attachments:
            if type(attachment) != list:
               fileName = os.path.basename(attachment)
               # Hard Coded path should be changed to being passed in
               relativeFileName = os.path.join(os.path.join('ModuleOutput', 'Email-Eml'), fileName)
               # Add derived file
               # Parameters Are:
               #    File Name, Local Rel Path, size, ctime, crtime, atime, mtime, isFile, Parent File, rederive Details, Tool Name, 
               #     Tool Version, Other Details, Encoding Type
               derived_file = skCase.addDerivedFile(fileName, relativeFileName, os.path.getsize(attachment), 0, 0, 0, 0, True, \
                                    bbArtifact, "", ProcessEmlEmailIngestModuleFactory.moduleName, "1.0", "", TskData.EncodingType.NONE)
               IngestServices.getInstance().fireModuleContentEvent(ModuleContentEvent(derived_file))

                

    def getDateTime(self, dateString, fileName):
        # Date format is 'Thu, 28 Jun 2012 19:21:12 -0700'    
        dateTuple = parsedate_tz(dateString)
        if dateTuple == None:
            self.log(Level.INFO, "No Date Specified " + fileName)
            return 0
        else:
            return mktime_tz(dateTuple)
   
       
class emlParser(object):
  #Class that defines parsing a directory of EML files.

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, rootDir, attachmentPath):
        """Initializes the database file object."""
        super(emlParser, self).__init__()
        # Path to directory where attachments will be stored:
        self.attachmentPath = attachmentPath
        self.rootDir = rootDir
        self.mailList = {}
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")

    def fileExists (self, f):
        """Checks whether extracted file was extracted before."""
        return os.path.exists(os.path.join(self.attachmentPath, f))

    def saveFile (self, fn, cont, filePath):
        """Saves cont to a file fn"""
        file = open(os.path.join(filePath, fn), "wb")
        file.write(cont)
        file.close()

    def constructName (self, id, fn):
        """Constructs a file name out of messages ID and packed file name"""
        id = id.split(".")
        id = id[0]+id[1]
        return id+"."+fn

    def disqo (self, s):
        """Removes double or single quotations."""
        s = s.strip()
        if s.startswith("'") and s.endswith("'"): return s[1:-1]
        if s.startswith('"') and s.endswith('"'): return s[1:-1]
        return s

    def disgra (self, s):
        """Removes < and > from HTML-like tag or e-mail address or e-mail ID."""
        s = s.strip()
        if s.startswith("<") and s.endswith(">"): return s[1:-1]
        return s

    def pullout (self, m, key, filePath):
        """Extracts content from an e-mail message.
        This works for multipart and nested multipart messages too.
        m   -- email.Message() or mailbox.Message()
        key -- Initial message ID (some string)
        Returns tuple(Text, Html, Files, Parts)
        Text  -- All text from all parts.
        Html  -- All HTMLs from all parts
        Files -- Dictionary mapping extracted file to message ID it belongs to.
        Parts -- Number of parts in original message.
        Attachments -- List of attachments for each message
        """
        Html = ""
        Text = ""
        Files = {}
        Parts = 0
        cfn = ""
        if not m.is_multipart():
            if m.get_filename(): # It's an attachment
                fn = m.get_filename()
                cfn = self.constructName(key, fn)
                Files[fn] = (cfn, None)
                if self.fileExists(cfn): return Text, Html, Files, 1, os.path.join(filePath, os.path.basename(cfn))
                self.saveFile(os.path.basename(cfn), m.get_payload(decode=True), filePath)
                return Text, Html, Files, 1, os.path.join(filePath, os.path.basename(cfn))
            # Not an attachment!
            # See where this belongs. Text, Html or some other data:
            cp = m.get_content_type()
            if cp=="text/plain": Text += m.get_payload(decode=True)
            elif cp=="text/html": Html += m.get_payload(decode=True)
            else:
                # Something else!
                # Extract a message ID and a file name if there is one:
                # This is some packed file and name is contained in content-type header
                # instead of content-disposition header explicitly
                cp = m.get("content-type")
                try: id = self.disgra(m.get("content-id"))
                except: id = None
                # Find file name:
                o = cp.find("name=")
                if o==-1: return Text, Html, Files, 1, ''
                ox = cp.find(";", o)
                if ox==-1: ox = None
                o += 5; fn = cp[o:ox]
                fn = self.disqo(fn)
                cfn = self.constructName(key, fn)
                Files[fn] = (cfn, id)
                if self.fileExists(cfn): return Text, Html, Files, 1, os.path.join(filePath, os.path.basename(cfn))
                self.saveFile(os.path.basename(cfn), m.get_payload(decode=True), filePath)
            return Text, Html, Files, 1, ''
        # This IS a multipart message.
        # So, we iterate over it and call pullout() recursively for each part.
        y = 0
        attachments = []
        while 1:
            # If we cannot get the payload, it means we hit the end:
            try:
                pl = m.get_payload(y)
            except: break
            # pl is a new Message object which goes back to pullout
            t, h, f, p, att = self.pullout(pl, key, filePath)
            if att != '':
                attachments.append(att)
            Text += t; Html += h; Files.update(f); Parts += p
            y += 1
        return Text, Html, Files, Parts, attachments

    def extract (self, msgfile, key, filePath):
        """Extracts all data from e-mail, including From, To, etc., and returns it as a dictionary.
        msgfile -- A file-like readable object
        key     -- Some ID string for that particular Message. Can be a file name or anything.
        Returns dict()
        Keys: from, to, subject, date, text, html, parts[, files]
        Key files will be present only when message contained binary files.
        For more see __doc__ for pullout() and caption() functions.
        """
        m = message_from_file(msgfile)
        From, To, Subject, Date, CC = self.caption(m)
        Text, Html, Files, Parts, Attachments = self.pullout(m, key, filePath)
        Text = Text.strip(); Html = Html.strip()
        msg = {"subject": Subject, "from": From, "to": To, "cc": CC, "date": Date,
            "text": Text, "html": Html, "parts": Parts, "attachments" : Attachments}
        return msg

    def caption (self, origin):
        """Extracts: To, From, Subject and Date from email.Message() or mailbox.Message()
        origin -- Message() object
        Returns tuple(From, To, Subject, Date)
        If message doesn't contain one/more of them, the empty strings will be returned.
        """
        Date = ""
        if origin.has_key("date"): Date = origin["date"].strip()
        From = ""
        if origin.has_key("from"): From = origin["from"].strip()
        To = ""
        if origin.has_key("to"):
            to = origin["to"].strip()
            To = re.findall(r'[\w\.-]+@[\w\.-]+', to)
        CC = ""
        if origin.has_key("cc"):
            cc = origin["cc"].strip()
            CC = re.findall(r'[\w\.-]+@[\w\.-]+', cc)
        Subject = ""
        if origin.has_key("subject"): Subject = origin["subject"].strip()
        return From, To, Subject, Date, CC

    def processEmls(self):
  
        for root, subFolders, files in os.walk(self.rootDir):
            for file in files:
                filePath = root + '\\' + file
                f = open(filePath, 'rb')
                #self.log(Level.INFO, "Processing Email File ==> " + file)
                msg = self.extract(f, f.name, self.attachmentPath)
                f.close()
                self.mailList[file] = msg

    def getEmlList(self):
        return self.mailList

