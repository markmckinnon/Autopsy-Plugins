# This python autopsy module will export the $UsnJrnl:$J and then call
# the command line version of the parseusn program.  A sqlite database that
# contains the NTFS UsrJrnl information is created then imported into the extracted
# view section of Autopsy.  The parseusn.exe program is a compiled modified version of the
# parseusn.py script created by Dave Lassalle, @superponible.
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

# Parse_Usnj.py module to parse the $UsnJrnl:$J file.
# Sept 2016
# 
# Comments 
#   Version 1.0 - Initial version - Sept 2016
# 

import jarray
import inspect
import os
#import subprocess
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


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ParseUsnJIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "USN Parser"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses The USN $J"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseUsnJIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ParseUsnJIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseUsnJIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_Events = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        if PlatformUtil.isWindowsOS():
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parseusn.exe")
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("Windows Executable was not found in module folder")
        elif PlatformUtil.getOSName() == 'Linux':
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'parseusn')
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("Linux Executable was not found in module folder")
        
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the SAM parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "$UsnJrnl:$J", "$Extend")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        temp_dir = os.path.join(Temp_Dir, "usnj")
        try:
		    os.mkdir(temp_dir)
        except:
		    self.log(Level.INFO, "Usnj Directory already exists " + temp_dir)
			
        for file in files:	
           # Check if the user pressed cancel while we were busy
           if self.context.isJobCancelled():
               return IngestModule.ProcessResult.OK

           #self.log(Level.INFO, "Processing file: " + file.getName())
           fileCount += 1

           # Save the DB locally in the temp folder. use file id as name to reduce collisions
           lclDbPath = os.path.join(temp_dir, "usnj.txt")
           ContentUtils.writeToFile(file, File(lclDbPath))
           self.log(Level.INFO, "Saved File ==> " + lclDbPath)

           # Run the EXE, saving output to a sqlite database
           #try:
           self.log(Level.INFO, "Running program ==> " + self.path_to_exe + " " + Temp_Dir + "\\usnj\\usnj.txt" + \
                    " " + Temp_Dir + "\\usnj.db3")
           pipe = Popen([self.path_to_exe, os.path.join(temp_dir, "usnj.txt"), os.path.join(temp_dir, "usnj.db3")], stdout=PIPE, stderr=PIPE)
           out_text = pipe.communicate()[0]
           self.log(Level.INFO, "Output from run is ==> " + out_text)               
               
           # Open the DB using JDBC
           lclDbPath = os.path.join(temp_dir, "usnj.db3")
           self.log(Level.INFO, "Path the system database file created ==> " + lclDbPath)
           
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) usnj.db3 (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
            
           # Query the contacts table in the database and get all columns. 
           try:
               stmt = dbConn.createStatement()
               resultSet = stmt.executeQuery("Select tbl_name from SQLITE_MASTER; ")
               self.log(Level.INFO, "query SQLite Master table")
           except SQLException as e:
               self.log(Level.INFO, "Error querying database for system table (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK

           try:
                self.log(Level.INFO, "Begin Create New Artifacts")
                artID_usnj = skCase.addArtifactType("TSK_USNJ", "NTFS UsrJrnl entries")
           except:		
                self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

           artID_usnj = skCase.getArtifactTypeID("TSK_USNJ")
           artID_usnj_evt = skCase.getArtifactType("TSK_USNJ")
             
           #self.log(Level.INFO, "get artifacts ID's " + str(artID_usnj))
           #self.log(Level.INFO, "get artifacts ID's " + str(resultSet))
           
             
           # Cycle through each row and create artifacts
           while resultSet.next():
               try: 
                   #self.log(Level.INFO, "Result (" + resultSet.getString("tbl_name") + ")")
                   table_name = resultSet.getString("tbl_name")
                   #self.log(Level.INFO, "Result get information from table " + resultSet.getString("tbl_name") + " ")
                   SQL_String_1 = "Select * from " + table_name + ";"
                   SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
                   #self.log(Level.INFO, SQL_String_1)
                   #self.log(Level.INFO, SQL_String_2)
				   
                   Column_Names = []
                   Column_Types = []
                   resultSet2  = stmt.executeQuery(SQL_String_2)
                   while resultSet2.next(): 
                      Column_Names.append(resultSet2.getString("name").upper())
                      Column_Types.append(resultSet2.getString("type"))
                      if resultSet2.getString("type").upper() == "TEXT":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_USNJ_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                              #self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + str(attID_ex1))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      else:
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_USNJ_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet2.getString("name"))
                              #self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + str(attID_ex1))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
										 
                   resultSet3 = stmt.executeQuery(SQL_String_1)
                   while resultSet3.next():
                      art = file.newArtifact(artID_usnj)
                      Column_Number = 1
                      for col_name in Column_Names:
                         #self.log(Level.INFO, "Result get information for column " + Column_Names[Column_Number - 1] + " ")
                         #self.log(Level.INFO, "Result get information for column " + Column_Types[Column_Number - 1] + " ")
                         #self.log(Level.INFO, "Result get information for column_number " + str(Column_Number) + " ")
                         c_name = "TSK_USNJ_" + col_name
                         #self.log(Level.INFO, "Attribute Name is " + c_name + " Atribute Type is " + str(Column_Types[Column_Number - 1]))
                         attID_ex1 = skCase.getAttributeType(c_name)
                         if Column_Types[Column_Number - 1] == "TEXT":
                             art.addAttribute(BlackboardAttribute(attID_ex1, ParseUsnJIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                         else:
                             art.addAttribute(BlackboardAttribute(attID_ex1, ParseUsnJIngestModuleFactory.moduleName, resultSet3.getInt(Column_Number)))
                         Column_Number = Column_Number + 1
						
               except SQLException as e:
                   self.log(Level.INFO, "Error getting values from usnj table (" + e.getMessage() + ")")

        # Clean up
           stmt.close()
           dbConn.close()
           # Fire an event to notify the UI and others that there are new artifacts  
           IngestServices.getInstance().fireModuleDataEvent(
               ModuleDataEvent(ParseUsnJIngestModuleFactory.moduleName, artID_usnj_evt, None))

		#Clean up EventLog directory and files
           os.remove(lclDbPath)
           try:
		      os.remove(os.path.join(temp_dir, "usnj.txt"))
           except:
		      self.log(Level.INFO, "removal of usnj.txt file failed " + temp_dir + "\\" + file.getName())
           try:
              os.rmdir(temp_dir)		
           except:
		      self.log(Level.INFO, "removal of usnj directory failed " + temp_dir)

        # After all databases, post a message to the ingest messages in box.
           message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Usnj Parser", " Usnj Has Been Analyzed " )
           IngestServices.getInstance().postMessage(message)

        # Fire an event to notify the UI and others that there are new artifacts  
           IngestServices.getInstance().fireModuleDataEvent(
               ModuleDataEvent(ParseUsnJIngestModuleFactory.moduleName, artID_usnj_evt, None))
        
        return IngestModule.ProcessResult.OK                
		
