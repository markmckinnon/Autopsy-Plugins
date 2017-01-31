# This python autopsy module will export/parse Mac OSX Safari.  A sqlite database that
# contains the Safari information is created then imported into the extracted
# view section of Autopsy.
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> Davenport [dot] edu]
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

# MacOSX Safari module to parse the Mac OSX Safari artifacts.
# January 2017
# 
# Comments 
#   Version 1.0 - Initial version - Jan 2017
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE
from urlparse import urlparse, parse_qs

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


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ParseMACOSXSafariIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Parse MACOSX Safari"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses Mac OSX Safari"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseMACOSXSafariIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ParseMACOSXSafariIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseMACOSXSafariIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_MACOSXART = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        self.path_to_safari_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plist_safari.exe")
        if not os.path.exists(self.path_to_safari_exe):
            raise IngestModuleException("plist_safari.exe was not found in module folder")
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process, Just before call to parse_safari_history")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        self.log(Level.INFO, "Starting 2 to process, Just before call to parse_safari_history")
        self.parse_safari_history(dataSource, progressBar)
        self.parse_safari_bookmarks(dataSource, progressBar)
        self.parse_safari_downloads(dataSource, progressBar)
        self.parse_safari_last_session(dataSource, progressBar)
        self.parse_safari_recently_closed_tabs(dataSource, progressBar)
        self.parse_safari_top_sites(dataSource, progressBar)
        self.log(Level.INFO, "ending process, Just before call to parse_safari_history")
        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Mac OSX Safari", " Safari Artifacts Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

    def parse_safari_history(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "History.db%", "%Users/%/Library/Safari")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Safari_History")
        except:
		    self.log(Level.INFO, "Safari History Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\Safari_History", file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        for file in files:
           if (file.getName() == "History.db"):
                # Example has only a Windows EXE, so bail if we aren't on Windows
                if not PlatformUtil.isWindowsOS(): 
                    self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
                    return IngestModule.ProcessResult.OK

               # Open the DB using JDBC
                lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory() + "\Safari_History", "History.db")
                self.log(Level.INFO, "Path the Safari History.db database file created ==> " + lclDbPath)
                try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
                
               # Query the history_visits table in the database and get all columns. 
                try:
                   stmt = dbConn.createStatement()
                   safari_history_sql = "Select a.url 'URL', b.visit_time + 978307200 'Date_Accessed', c.url 'Referrer_URL', " + \
                                        " b.title 'Title', 'Safari' 'Program_Name' from history_visits b " + \
                                        " left join history_items a on a.id = b.history_item left join history_items c on c.id = b.redirect_source;"
                   self.log(Level.INFO, safari_history_sql)
                   resultSet = stmt.executeQuery(safari_history_sql)
                   self.log(Level.INFO, "query History table")
                except SQLException as e:
                   self.log(Level.INFO, "Error querying database for history table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

                artifact_name = "TSK_WEB_HISTORY"
                artID_hst = skCase.getArtifactTypeID(artifact_name)
                artID_hst_evt = skCase.getArtifactType(artifact_name)

               # Cycle through each row and create artifacts
                while resultSet.next():
                   try: 
                       #self.log(Level.INFO, SQL_String_1)
                       #self.log(Level.INFO, SQL_String_2)
                       
                       art = file.newArtifact(artID_hst)
                       self.log(Level.INFO, "Inserting attribute URL")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("URL")))
                       self.log(Level.INFO, "Inserting attribute Date_Accessed")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("Date_Accessed")))
                       self.log(Level.INFO, "Inserting attribute Referer")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_REFERRER.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Referrer_URL")))
                       self.log(Level.INFO, "Inserting attribute Title")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Title")))
                       self.log(Level.INFO, "Inserting attribute PROG_NAME")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Program_Name")))
                       try:
                          slashparts = resultSet.getString("URL").split('/')
                          self.log(Level.INFO, "Inserting attribute Domain " + slashparts[0] + " " + slashparts[1] + " " + slashparts[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, slashparts[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))
                       try:
                          userpath = file.getParentPath()
                          username = userpath.split('/')
                          self.log(Level.INFO, "Getting Username " + username[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, username[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))

                       query_string = parse_qs(urlparse(resultSet.getString("URL")).query)
                       if ('q' in query_string):
                           artID_srch = skCase.getArtifactTypeID("TSK_WEB_SEARCH_QUERY")
                           artID_srch_evt = skCase.getArtifactType("TSK_WEB_SEARCH_QUERY")
                           try: 
                               #self.log(Level.INFO, SQL_String_1)
                               #self.log(Level.INFO, SQL_String_2)
                               
                               art_srch = file.newArtifact(artID_srch)
                               self.log(Level.INFO, "Inserting attribute URL")
                               try:
                                  slashparts = resultSet.getString("URL").split('/')
                                  self.log(Level.INFO, "Inserting attribute Domain " + slashparts[0] + " " + slashparts[1] + " " + slashparts[2]   )
                                  art_srch.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, slashparts[2]))
                               except:
                                  art_srch.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))
                               self.log(Level.INFO, "Inserting attribute Text")
                               art_srch.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, str(query_string['q'][0])))
                               self.log(Level.INFO, "Inserting attribute PROG_NAME")
                               art_srch.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Program_Name")))
                               self.log(Level.INFO, "Inserting attribute Date_Accessed")
                               art_srch.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("Date_Accessed")))
                               self.log(Level.INFO, "Inserting attribute PROG_NAME")
                               art_srch.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Program_Name")))
                               try:
                                  userpath = file.getParentPath()
                                  username = userpath.split('/')
                                  self.log(Level.INFO, "Getting Username " + username[2]   )
                                  art_srch.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, username[2]))
                               except:
                                  art_srch.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))

                               IngestServices.getInstance().fireModuleDataEvent(
                                       ModuleDataEvent(ParseMACOSXSafariIngestModuleFactory.moduleName, artID_srch_evt, None))
                                       
                           except SQLException as e:
                               self.log(Level.INFO, "Error getting values from web_history table (" + e.getMessage() + ")")

                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from web_history table (" + e.getMessage() + ")")

                IngestServices.getInstance().fireModuleDataEvent(
                       ModuleDataEvent(ParseMACOSXSafariIngestModuleFactory.moduleName, artID_hst_evt, None))

                stmt.close()
                dbConn.close()

                # Clean up
                os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        for file in files:
           try:
              os.remove(Temp_Dir + "\\" + file.getName())
           except:
              self.log(Level.INFO, "removal of Safari History file failed " + Temp_Dir + "\\" + file.getName())
        try:
           os.rmdir(Temp_Dir)		
        except:
		   self.log(Level.INFO, "removal of Safari History directory failed " + Temp_Dir)
    
    def parse_safari_downloads(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "Downloads.plist", "%Users/%/Library/Safari")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Safari_downloads")
        except:
		    self.log(Level.INFO, "Safari downloads Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\Safari_downloads", file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        #file = files[0]
        for file in files:
           if (file.getName() == "Downloads.plist"):
                # Example has only a Windows EXE, so bail if we aren't on Windows
                if not PlatformUtil.isWindowsOS(): 
                    self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
                    return IngestModule.ProcessResult.OK

                # Run the program plist_safari.exe 
                self.log(Level.INFO, "Running program ==> " + self.path_to_safari_exe + " " + Temp_Dir + "\\Safari_downloads\\" + \
                         "downloads.plist" + Temp_Dir + " \\downloads.db3 downloads ")
                pipe = Popen([self.path_to_safari_exe, Temp_Dir + "\\Safari_downloads\\downloads.plist", Temp_Dir + \
                          "\\downloads.db3", "downloads"], stdout=PIPE, stderr=PIPE)
                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text)               
              
               # Open the DB using JDBC
                lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "downloads.db3")
                self.log(Level.INFO, "Path the Safari downloads.db3 database file created ==> " + lclDbPath)
                try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
                
               # Query the downloads table in the database and get all columns. 
                try:
                   stmt = dbConn.createStatement()
                   safari_downloads_sql = "Select DownloadEntryPath 'PATH', DownloadEntryURL 'URL', " \
                                        " strftime('%s',datetime(substr(DownloadEntryDateAddedKey,1,19))) 'Date_Accessed', 'Safari' 'Program_Name' " \
                                        " from downloads;"
                   self.log(Level.INFO, safari_downloads_sql)
                   resultSet = stmt.executeQuery(safari_downloads_sql)
                   self.log(Level.INFO, "query downloads table")
                except SQLException as e:
                   self.log(Level.INFO, "Error querying database for downloads table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

                artifact_name = "TSK_WEB_DOWNLOAD"
                artID_web = skCase.getArtifactTypeID(artifact_name)
                artID_web_evt = skCase.getArtifactType(artifact_name)

               # Cycle through each row and create artifacts
                while resultSet.next():
                   try: 
                       #self.log(Level.INFO, SQL_String_1)
                       #self.log(Level.INFO, SQL_String_2)
                       
                       art = file.newArtifact(artID_web)
                       self.log(Level.INFO, "Inserting attribute Path")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Path")))
                       self.log(Level.INFO, "Inserting attribute URL")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("URL")))
                       self.log(Level.INFO, "Inserting attribute Date_Accessed")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("Date_Accessed")))
                       self.log(Level.INFO, "Inserting attribute PROG_NAME")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Program_Name")))
                       try:
                          slashparts = resultSet.getString("URL").split('/')
                          self.log(Level.INFO, "Inserting attribute Domain " + slashparts[0] + " " + slashparts[1] + " " + slashparts[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, slashparts[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))
                       try:
                          userpath = file.getParentPath()
                          username = userpath.split('/')
                          self.log(Level.INFO, "Getting Username " + username[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, username[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))

                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from the downloads table (" + e.getMessage() + ")")

                IngestServices.getInstance().fireModuleDataEvent(
                       ModuleDataEvent(ParseMACOSXSafariIngestModuleFactory.moduleName, artID_web_evt, None))

                stmt.close()
                dbConn.close()

                # Clean up
                os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        for file in files:
           try:
              os.remove(Temp_Dir + "\\" + file.getName())
           except:
              self.log(Level.INFO, "removal of Safari Downloads file failed " + Temp_Dir + "\\" + file.getName())
        try:
           os.rmdir(Temp_Dir)		
        except:
		   self.log(Level.INFO, "removal of Safari Download directory failed " + Temp_Dir)

    def parse_safari_bookmarks(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "Bookmarks.plist", "%Users/%/Library/Safari")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Safari_Bookmarks")
        except:
		    self.log(Level.INFO, "Safari bookmarks Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\Safari_bookmarks", file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        #file = files[0]
        for file in files:
           if (file.getName() == "Bookmarks.plist"):
                # Example has only a Windows EXE, so bail if we aren't on Windows
                if not PlatformUtil.isWindowsOS(): 
                    self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
                    return IngestModule.ProcessResult.OK

                # Run the program plist_safari.exe 
                self.log(Level.INFO, "Running program ==> " + self.path_to_safari_exe + " " + Temp_Dir + "\\Safari_bookmarks\\" + \
                         "Bookmarks.plist" + Temp_Dir + " \\bookmarks.db3 bookmarks ")
                pipe = Popen([self.path_to_safari_exe, Temp_Dir + "\\Safari_bookmarks\\Bookmarks.plist", Temp_Dir + \
                          "\\bookmarks.db3", "bookmarks"], stdout=PIPE, stderr=PIPE)
                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text)               
              
               # Open the DB using JDBC
                lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "bookmarks.db3")
                self.log(Level.INFO, "Path the Safari bookmarks.db3 database file created ==> " + lclDbPath)
                try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
                
               # Query the bookmarks table in the database and get all columns. 
                try:
                   stmt = dbConn.createStatement()
                   #safari_downloads_sql = "select title, urlstring 'URL', strftime('%s',datetime(substr(DateAdded,1,19))) 'Date_Created', " + \
                   safari_downloads_sql = "select title, urlstring 'URL', " + \
                                          " 'SAFARI' 'PROGRAM' from bookmarks where webbookmarktype = 'WebBookmarkTypeLeaf';"
                   self.log(Level.INFO, safari_downloads_sql)
                   resultSet = stmt.executeQuery(safari_downloads_sql)
                   self.log(Level.INFO, "query downloads table")
                except SQLException as e:
                   self.log(Level.INFO, "Error querying database for downloads table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

                artifact_name = "TSK_WEB_BOOKMARK"
                artID_book = skCase.getArtifactTypeID(artifact_name)
                artID_book_evt = skCase.getArtifactType(artifact_name)

               # Cycle through each row and create artifacts
                while resultSet.next():
                   try: 
                       #self.log(Level.INFO, SQL_String_1)
                       #self.log(Level.INFO, SQL_String_2)
                       
                       art = file.newArtifact(artID_book)
                       self.log(Level.INFO, "Inserting attribute URL")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("URL")))
                       self.log(Level.INFO, "Inserting attribute Title")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Title")))
                       #self.log(Level.INFO, "Inserting attribute Date_Created")
                       #art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("Date_Created")))
                       self.log(Level.INFO, "Inserting attribute PROG_NAME")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Program_Name")))
                       try:
                          slashparts = resultSet.getString("URL").split('/')
                          self.log(Level.INFO, "Inserting attribute Domain " + slashparts[0] + " " + slashparts[1] + " " + slashparts[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, slashparts[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))
                       try:
                          userpath = file.getParentPath()
                          username = userpath.split('/')
                          self.log(Level.INFO, "Getting Username " + username[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, username[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))

                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from bookmarks table (" + e.getMessage() + ")")

                IngestServices.getInstance().fireModuleDataEvent(
                       ModuleDataEvent(ParseMACOSXSafariIngestModuleFactory.moduleName, artID_book_evt, None))

                stmt.close()
                dbConn.close()

                # Clean up
                os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        for file in files:
           try:
              os.remove(Temp_Dir + "\\" + file.getName())
           except:
              self.log(Level.INFO, "removal of Safari bookmarks file failed " + Temp_Dir + "\\" + file.getName())
        try:
           os.rmdir(Temp_Dir)		
        except:
		   self.log(Level.INFO, "removal of Safari bookmarks directory failed " + Temp_Dir)
           
    def parse_safari_last_session(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "LastSession.plist", "%Users/%/Library/Safari")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Safari_lastsession")
        except:
		    self.log(Level.INFO, "Safari last Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\Safari_lastsession", file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        #file = files[0]
        for file in files:
           if (file.getName() == "LastSession.plist"):
                # Example has only a Windows EXE, so bail if we aren't on Windows
                if not PlatformUtil.isWindowsOS(): 
                    self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
                    return IngestModule.ProcessResult.OK

                # Run the program plist_safari.exe 
                self.log(Level.INFO, "Running program ==> " + self.path_to_safari_exe + " " + Temp_Dir + "\\Safari_lastsession\\" + \
                         "lastsession.plist" + Temp_Dir + " \\lastsession.db3 lastsession ")
                pipe = Popen([self.path_to_safari_exe, Temp_Dir + "\\Safari_downloads\\lastsession.plist", Temp_Dir + \
                          "\\lastsession.db3", "lastsession"], stdout=PIPE, stderr=PIPE)
                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text)               
              
               # Open the DB using JDBC
                lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "lastsession.db3")
                self.log(Level.INFO, "Path the Safari lastsession.db3 database file created ==> " + lclDbPath)
                try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
                
               # Create the safari last session artifact
                try:
                     self.log(Level.INFO, "Begin Create New Artifacts")
                     artID_ls = skCase.addArtifactType( "TSK_SAFARI_LASTSESSION", "Safari Last Session")
                except:		
                     self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

               # Create the artifacts need for lastsession
                try:
                   attID_lvt = skCase.addArtifactAttributeType("TSK_LAST_VISIT_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last Visit Time")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Last Visit Time ==> ")
                try:
                   attID_dtc = skCase.addArtifactAttributeType("TSK_DATE_CLOSED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Date Closed")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Date Closed ==> ")
                try:
                   attID_prw = skCase.addArtifactAttributeType("TSK_PRIVATE_WINDOW", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Private Window")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Private Window ==> ")
                try:
                   attID_puw = skCase.addArtifactAttributeType("TSK_POPUP_WINDOW", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Popup Window")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Popup Window ==> ")
                try:
                   attID_sen = skCase.addArtifactAttributeType("TSK_SESSION_ENCRYPTED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Session Encrypted")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Session Encrypted ==> ")
                     
                # Get the artifact and attributes
                artID_ls = skCase.getArtifactTypeID("TSK_SAFARI_LASTSESSION")
                artID_ls_evt = skCase.getArtifactType("TSK_SAFARI_LASTSESSION")
                attID_lvt = skCase.getAttributeType("TSK_LAST_VISIT_TIME")
                attID_dtc = skCase.getAttributeType("TSK_DATE_CLOSED")
                attID_prw = skCase.getAttributeType("TSK_PRIVATE_WINDOW")
                attID_puw = skCase.getAttributeType("TSK_POPUP_WINDOW")
                attID_sen = skCase.getAttributeType("TSK_SESSION_ENCRYPTED")
                
               # Query the lastsession table in the database and get all columns. 
                try:
                   stmt = dbConn.createStatement()
                   safari_lastsession_sql = "select strftime('%s', datetime(lastvisittime + 978307200,'unixepoch')) 'LAST_VISIT_TIME', " + \
                                          " tabtitle 'TITLE', taburl 'URL', strftime('%s',datetime(substr(DateClosed,1,19))) 'DATE_CLOSED', " + \
                                          " isPrivateWindow 'PRIVATE_WINDOW', Ispopupwindow 'POPUP_WINDOW', " + \
                                          " sessionstateisencrypted 'State_Encrypted' from lastsession where taburl != '' or tabtitle != '';"
                   self.log(Level.INFO, safari_lastsession_sql)
                   resultSet = stmt.executeQuery(safari_lastsession_sql)
                   self.log(Level.INFO, "query lastsession table")
                except SQLException as e:
                   self.log(Level.INFO, "Error querying database for lastsession table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

               # Cycle through each row and create artifacts
                while resultSet.next():
                   try: 
                       #self.log(Level.INFO, SQL_String_1)
                       #self.log(Level.INFO, SQL_String_2)
                       
                       art = file.newArtifact(artID_ls)
                       self.log(Level.INFO, "Inserting attribute URL")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("URL")))
                       self.log(Level.INFO, "Inserting attribute TITLE")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Title")))
                       self.log(Level.INFO, "Inserting attribute Last Visit Date")
                       art.addAttribute(BlackboardAttribute(attID_lvt, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("LAST_VISIT_TIME")))
                       self.log(Level.INFO, "Inserting attribute Date Closed")
                       art.addAttribute(BlackboardAttribute(attID_dtc, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("Date_Closed")))
                       self.log(Level.INFO, "Inserting attribute Private Window")
                       art.addAttribute(BlackboardAttribute(attID_prw, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("PRIVATE_WINDOW")))
                       self.log(Level.INFO, "Inserting attribute popup window")
                       art.addAttribute(BlackboardAttribute(attID_puw, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("POPUP_WINDOW")))
                       self.log(Level.INFO, "Inserting attribute Session Encrypted")
                       art.addAttribute(BlackboardAttribute(attID_sen, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("State_Encrypted")))
                       try:
                          slashparts = resultSet.getString("URL").split('/')
                          self.log(Level.INFO, "Inserting attribute Domain " + slashparts[0] + " " + slashparts[1] + " " + slashparts[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, slashparts[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))
                       try:
                          userpath = file.getParentPath()
                          username = userpath.split('/')
                          self.log(Level.INFO, "Getting Username " + username[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, username[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))

                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from the lastsession table (" + e.getMessage() + ")")

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseMACOSXSafariIngestModuleFactory.moduleName, artID_ls_evt, None))

                stmt.close()
                dbConn.close()

                # Clean up
                os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        for file in files:
           try:
              os.remove(Temp_Dir + "\\" + file.getName())
           except:
              self.log(Level.INFO, "removal of Safari lastsession file failed " + Temp_Dir + "\\" + file.getName())
        try:
           os.rmdir(Temp_Dir)		
        except:
		   self.log(Level.INFO, "removal of Safari session directory failed " + Temp_Dir)

    def parse_safari_recently_closed_tabs(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "RecentlyClosedTabs.plist", "%Users/%/Library/Safari")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Safari_recentlyclosed")
        except:
		    self.log(Level.INFO, "Safari recently closed tabs Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\Safari_recentlyclosed", file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        #file = files[0]
        for file in files:
           if (file.getName() == "RecentlyClosedTabs.plist"):
                # Example has only a Windows EXE, so bail if we aren't on Windows
                if not PlatformUtil.isWindowsOS(): 
                    self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
                    return IngestModule.ProcessResult.OK

                # Run the program plist_safari.exe 
                self.log(Level.INFO, "Running program ==> " + self.path_to_safari_exe + " " + Temp_Dir + "\\Safari_recentlyclosed\\" + \
                         "recentlyclosedtabs.plist" + Temp_Dir + " \\recentlyclosedtabs.db3 recentlyclosedtabs ")
                pipe = Popen([self.path_to_safari_exe, Temp_Dir + "\\Safari_recentlyclosed\\recentlyclosedtabs.plist", Temp_Dir + \
                          "\\recentlyclosedtabs.db3", "recentlyclosedtabs"], stdout=PIPE, stderr=PIPE)
                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text)               
              
               # Open the DB using JDBC
                lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "recentlyclosedtabs.db3")
                self.log(Level.INFO, "Path the Safari recentlyclosedtabs.db3 database file created ==> " + lclDbPath)
                try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
                
               # Create the safari last session artifact
                try:
                     self.log(Level.INFO, "Begin Create New Artifacts")
                     artID_rc = skCase.addArtifactType( "TSK_SAFARI_RECENTLYCLOSED", "Safari Recently Closed Tabs")
                except:		
                     self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

               # Create the artifacts need for lastsession
                try:
                   attID_lvt = skCase.addArtifactAttributeType("TSK_LAST_VISIT_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last Visit Time")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Last Visit Time ==> ")
                try:
                   attID_dtc = skCase.addArtifactAttributeType("TSK_DATE_CLOSED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Date Closed")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Date Closed ==> ")
                try:
                   attID_sen = skCase.addArtifactAttributeType("TSK_SESSION_ENCRYPTED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Session Encrypted")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Session Encrypted ==> ")
                     
                # Get the artifact and attributes
                artID_rc = skCase.getArtifactTypeID("TSK_SAFARI_RECENTLYCLOSED")
                artID_rc_evt = skCase.getArtifactType("TSK_SAFARI_RECENTLYCLOSED")
                attID_lvt = skCase.getAttributeType("TSK_LAST_VISIT_TIME")
                attID_dtc = skCase.getAttributeType("TSK_DATE_CLOSED")
                attID_sen = skCase.getAttributeType("TSK_SESSION_ENCRYPTED")
                
               # Query the recentlyclosedtabs table in the database and get all columns. 
                try:
                   stmt = dbConn.createStatement()
                   safari_lastsession_sql = "select strftime('%s', datetime(lastvisittime + 978307200,'unixepoch')) 'LAST_VISIT_TIME', " + \
                                          " tabtitle 'TITLE', taburl 'URL', strftime('%s',datetime(substr(DateClosed,1,19))) 'DATE_CLOSED', " + \
                                          " sessionstateisencrypted 'State_Encrypted' from recentlyclosedtabs where taburl != '' or tabtitle != '';"
                   self.log(Level.INFO, safari_lastsession_sql)
                   resultSet = stmt.executeQuery(safari_lastsession_sql)
                   self.log(Level.INFO, "query recentlyclosedtabs table")
                except SQLException as e:
                   self.log(Level.INFO, "Error querying database for recentlyclosedtabs table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

               # Cycle through each row and create artifacts
                while resultSet.next():
                   try: 
                       #self.log(Level.INFO, SQL_String_1)
                       #self.log(Level.INFO, SQL_String_2)
                       
                       art = file.newArtifact(artID_rc)
                       self.log(Level.INFO, "Inserting attribute URL")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("URL")))
                       self.log(Level.INFO, "Inserting attribute TITLE")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Title")))
                       self.log(Level.INFO, "Inserting attribute Last Visit Date")
                       art.addAttribute(BlackboardAttribute(attID_lvt, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("LAST_VISIT_TIME")))
                       self.log(Level.INFO, "Inserting attribute Date Closed")
                       art.addAttribute(BlackboardAttribute(attID_dtc, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("Date_Closed")))
                       self.log(Level.INFO, "Inserting attribute Session Encrypted")
                       art.addAttribute(BlackboardAttribute(attID_sen, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("State_Encrypted")))
                       try:
                          slashparts = resultSet.getString("URL").split('/')
                          self.log(Level.INFO, "Inserting attribute Domain " + slashparts[0] + " " + slashparts[1] + " " + slashparts[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, slashparts[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))
                       try:
                          userpath = file.getParentPath()
                          username = userpath.split('/')
                          self.log(Level.INFO, "Getting Username " + username[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, username[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))

                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from the recentlyclosedtabs table (" + e.getMessage() + ")")

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseMACOSXSafariIngestModuleFactory.moduleName, artID_rc_evt, None))

                stmt.close()
                dbConn.close()

                # Clean up
                os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        for file in files:
           try:
              os.remove(Temp_Dir + "\\" + file.getName())
           except:
              self.log(Level.INFO, "removal of Safari recentlyclosedtabs file failed " + Temp_Dir + "\\" + file.getName())
        try:
           os.rmdir(Temp_Dir)		
        except:
		   self.log(Level.INFO, "removal of Safari recentlyclosed directory failed " + Temp_Dir)

    def parse_safari_top_sites(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "TopSites.plist", "%Users/%/Library/Safari")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Safari_topsites")
        except:
		    self.log(Level.INFO, "Safari topsites Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\Safari_topsites", file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        #file = files[0]
        for file in files:
           if (file.getName() == "TopSites.plist"):
                # Example has only a Windows EXE, so bail if we aren't on Windows
                if not PlatformUtil.isWindowsOS(): 
                    self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
                    return IngestModule.ProcessResult.OK

                # Run the program plist_safari.exe 
                self.log(Level.INFO, "Running program ==> " + self.path_to_safari_exe + " " + Temp_Dir + "\\Safari_topsites\\" + \
                         " topsites.plist" + Temp_Dir + " \\topsites.db3 topsites ")
                pipe = Popen([self.path_to_safari_exe, Temp_Dir + "\\Safari_topsites\\topsites.plist", Temp_Dir + \
                          "\\topsites.db3", "topsites"], stdout=PIPE, stderr=PIPE)
                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text)               
              
               # Open the DB using JDBC
                lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "topsites.db3")
                self.log(Level.INFO, "Path the Safari topsites.db3 database file created ==> " + lclDbPath)
                try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
                
               # Create the safari last session artifact
                try:
                     self.log(Level.INFO, "Begin Create New Artifacts")
                     artID_ts = skCase.addArtifactType( "TSK_SAFARI_TOPSITES", "Safari Top Sites")
                except:		
                     self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

               # Create the artifacts need for lastsession
                try:
                   attID_slm = skCase.addArtifactAttributeType("TSK_SITE_LAST_MOD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Site Last Modified")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Last Visit Time ==> ")
                try:
                   attID_sbi = skCase.addArtifactAttributeType("TSK_SAFARI_SITE_BUILT_IN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Site Built In")
                except:		
                     self.log(Level.INFO, "Attributes Creation Error, Site Built In ==> ")
                     
                # Get the artifact and attributes
                artID_ts = skCase.getArtifactTypeID("TSK_SAFARI_TOPSITES")
                artID_ts_evt = skCase.getArtifactType("TSK_SAFARI_TOPSITES")
                attID_slm = skCase.getAttributeType("TSK_SITE_LAST_MOD")
                attID_sbi = skCase.getAttributeType("TSK_SAFARI_SITE_BUILT_IN")
                
               # Query the topsites table in the database and get all columns. 
                try:
                   stmt = dbConn.createStatement()
                   safari_topsites_sql = "select topsiteURLString 'URL', TopsiteTitle 'Title', " + \
                                            " strftime('%s',datetime(substr(DisplayedSitesLastModified,1,19))) 'SITE_LAST_MODIFIED', " + \
                                            " TopSiteIsBuiltIn 'SITE_BUILT_IN' from topsites;"
                   self.log(Level.INFO, safari_topsites_sql)
                   resultSet = stmt.executeQuery(safari_topsites_sql)
                   self.log(Level.INFO, "query topsites table")
                except SQLException as e:
                   self.log(Level.INFO, "Error querying database for topsites table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

               # Cycle through each row and create artifacts
                while resultSet.next():
                   try: 
                       #self.log(Level.INFO, SQL_String_1)
                       #self.log(Level.INFO, SQL_String_2)
                       
                       art = file.newArtifact(artID_ts)
                       self.log(Level.INFO, "Inserting attribute URL")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("URL")))
                       self.log(Level.INFO, "Inserting attribute TITLE")
                       art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("Title")))
                       self.log(Level.INFO, "Inserting attribute Last Mod Date")
                       art.addAttribute(BlackboardAttribute(attID_slm, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getInt("SITE_LAST_MODIFIED")))
                       self.log(Level.INFO, "Inserting attribute Site Built In")
                       art.addAttribute(BlackboardAttribute(attID_sbi, ParseMACOSXSafariIngestModuleFactory.moduleName, resultSet.getString("SITE_BUILT_IN")))
                       try:
                          slashparts = resultSet.getString("URL").split('/')
                          self.log(Level.INFO, "Inserting attribute Domain " + slashparts[0] + " " + slashparts[1] + " " + slashparts[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, slashparts[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))
                       try:
                          userpath = file.getParentPath()
                          username = userpath.split('/')
                          self.log(Level.INFO, "Getting Username " + username[2]   )
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, username[2]))
                       except:
                          art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), ParseMACOSXSafariIngestModuleFactory.moduleName, ""))

                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from the topsites table (" + e.getMessage() + ")")

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseMACOSXSafariIngestModuleFactory.moduleName, artID_ts_evt, None))
                
                stmt.close()
                dbConn.close()

                # Clean up
                os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        for file in files:
           try:
              os.remove(Temp_Dir + "\\" + file.getName())
           except:
              self.log(Level.INFO, "removal of Safari lastsession file failed " + Temp_Dir + "\\" + file.getName())
        try:
           os.rmdir(Temp_Dir)		
        except:
		   self.log(Level.INFO, "removal of Safari session directory failed " + Temp_Dir)

