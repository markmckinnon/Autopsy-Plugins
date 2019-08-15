# This python autopsy module will Parse an iTunes backup and add the files back 
# in as a datasource.
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

# iTunes_Backup.py.
# June 2019
# 
# Comments 
#   Version 1.0 - Initial version - June 2019
# 

import os
import shutil
import inspect
import string
import re

from java.lang import Class
from java.util import UUID
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
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule import AddLocalFilesTask
from org.sleuthkit.autopsy.casemodule.services.FileManager import FileAddProgressUpdater


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class iTunesBackupIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "iTunes Backup Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parse an iTunes Backup"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def hasIngestJobSettingsPanel(self):
        return False

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return iTunesBackupIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class iTunesBackupIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(iTunesBackupIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
 
    # Where any setup and configuration is done
    def startUp(self, context):
        self.context = context
        
    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Create iTunes directory in temp directory, if it exists then continue on processing		
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "iTunes")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
		    os.mkdir(tempDir)
        except:
		    self.log(Level.INFO, "iTunes Directory already exists " + tempDir)

        # Create iTunes directory in modules directory, if it exists then continue on processing		
        modDir = os.path.join(Case.getCurrentCase().getModuleDirectory(), "iTunes")
        self.log(Level.INFO, "create Directory " + modDir)
        try:
		    os.mkdir(modDir)
        except:
		    self.log(Level.INFO, "iTunes Directory already exists " + modDir)

        files = fileManager.findFiles(dataSource, "Manifest.db", "Apple Computer/MobileSync/Backup/")
        numFiles = len(files)
        self.log(Level.INFO, "Number of Manifestdb Files found ==> " + str(numFiles))
        
        for file in files:
        
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Parent Path ==> " + str(file.getParentPath()))
            if "Apple Computer/MobileSync/Backup/" in file.getParentPath():
                #self.log(Level.INFO, str(file))            
                # This is to get the base directory of the itunes backup incase there is more then one backup
                (head, tail) = os.path.split(file.getParentPath())
                (head2, backupDir) = os.path.split(head)
                self.log(Level.INFO, "Backup Dir is ==> " + backupDir)
                try:
                    os.mkdir(os.path.join(modDir, backupDir))
                except:
                    self.log(Level.INFO, "Failed to create directory " + os.path.join(modDir, backupDir))

                # Save the DB locally in the temp folder. use file id as name to reduce collisions
                lclDbPath = os.path.join(tempDir, str(file.getId()) + "-" + file.getName())
                ContentUtils.writeToFile(file, File(lclDbPath))
                # Process the SAM Registry File getting the Username and RID
                dbConnection = self.connnectToManifestDb(lclDbPath)
                fileInfo = self.processManifestDb(dbConnection, os.path.join(modDir, backupDir))
                dbConnection.close()
#                self.log(Level.INFO, str(fileInfo))
                self.writeBackupFiles(fileInfo, os.path.join(modDir, backupDir), file.getParentPath(), fileManager, dataSource)
            else:
                self.log(Level.INFO, "Skipping File " + file.getName() + " In Path " + file.getParentPath())

        # Add Backup Files back into Autopsy as its own Data Sourse
        self.addBackupFilesToDataSource(dataSource, modDir)
        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "ItunesBackup", " Itunes Backup has been analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                

    def addBackupFilesToDataSource(self, dataSource, modDir):

        progressUpdater = ProgressUpdater()  
        newDataSources = []        
     
        dirList = []
        dirList.append(modDir)
     
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        skCase = Case.getCurrentCase()

        deviceId = UUID.randomUUID()

        skCase.notifyAddingDataSource(deviceId)   

        # Add data source with files
        newDataSource = fileManager.addLocalFilesDataSource(str(deviceId), "Itunes Backup", "", dirList, progressUpdater)
            
        newDataSources.append(newDataSource.getRootDirectory())
           
        # Get the files that were added
        filesAdded = progressUpdater.getFiles()
        #self.log(Level.INFO, "Fire Module1: ==> " + str(files_added))
            
        for fileAdded in filesAdded:
            skCase.notifyDataSourceAdded(fileAdded, deviceId)
            #self.log(Level.INFO, "Fire Module1: ==> " + str(file_added))
        
        
    def writeBackupFiles(self, fileInfo, modDir, parentPath, fileManager, dataSource):

        for fInfo in fileInfo:
            files = fileManager.findFiles(dataSource, fInfo[1], parentPath)
            numFiles = len(files)
            
            for file in files:
                (head, tail) = os.path.split(fInfo[2])
                ContentUtils.writeToFile(file, File(os.path.join(head, self.validFileName(tail))))
   
    def validFileName(self, fileName):
    
        validChars = "-_.() %s%s" % (string.ascii_letters, string.digits)
        fName = ''.join(c for c in fileName if c in validChars)
        return fName
        
    def connnectToManifestDb(self, dbFile):
       try: 
           Class.forName("org.sqlite.JDBC").newInstance()
           dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % dbFile)
       except SQLException as e:
           self.log(Level.INFO, "Could not open database file (not SQLite) " + extractedFile + " (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK
           
       return dbConn
        
    def processManifestDb(self, dbConn, modDir):
    
       # Query the Files table in the database. 
       try:
           stmtDir = dbConn.createStatement()
           resultSetDir = stmtDir.executeQuery("select domain, relativePath from Files where flags = 2;")
           self.log(Level.INFO, "query Files table for Directory Information")
       except SQLException as e:
           self.log(Level.INFO, "Error querying database for files table (" + e.getMessage() + ") extractedFile ==> " + extractedFile)
           return IngestModule.ProcessResult.OK
        
       dirName = "" 
       while resultSetDir.next():
           try: 
               dirName = os.path.join(modDir, resultSetDir.getString("domain"), resultSetDir.getString("relativePath"))
               try:
                   os.makedirs(dirName)
               except:
                   self.log(Level.INFO, "Directory already exists ==> " + dirName)
           except SQLException as e:
               #pass
               self.log(Level.INFO, "Error creating Directory " + dirName + " (" + e.getMessage() + ")")
               
       try:
           stmtFiles = dbConn.createStatement()
           resultSetFiles = stmtFiles.executeQuery("select substr(fileID, 1, 2) dir, fileID, domain, relativePath from Files where flags = 1;")
           self.log(Level.INFO, "query Files table for Directory Information")
       except SQLException as e:
           self.log(Level.INFO, "Error querying database for files table (" + e.getMessage() + ") ")
           return IngestModule.ProcessResult.OK
        
       filesInfo = []     
       while resultSetFiles.next():
           try: 
               fInfo = []
               fInfo.append(resultSetFiles.getString("dir"))
               fInfo.append(resultSetFiles.getString("fileID"))
               fInfo.append(os.path.join(modDir, resultSetFiles.getString("domain"), resultSetFiles.getString("relativePath")))
               filesInfo.append(fInfo) 
           except SQLException as e:
               #pass
               self.log(Level.INFO, "Error getting Files " + " (" + e.getMessage() + ")")

       return filesInfo

       
class ProgressUpdater(FileAddProgressUpdater):

    def __init__(self):
        self.files = []
        pass
    
    def fileAdded(self, newfile):
        self.files.append(newfile)
        #pass
        #progressBar.progress("Processing Recently Used Apps")	
        
    def getFiles(self):
        return self.files
