# This python autopsy module will export the WebcacheV01 file and then call
# the command line version of the Export_Esedb.  A sqlite database that
# contains the Webcache information is created then imported into the extracted
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

# Webcache Parser module to parse the webcache file for each user in windows.
# June 2016
# 
# Comments 
#   Version 1.0 - Initial version - June 2016
#   Version 1.1 - Added custom artifacts/attributes - September 1, 2016
# 

import jarray
import inspect
import os
import subprocess
import sys

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
class ParseWebcacheIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Parse WebCache"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Sample module that parses the Copies the prefetch files and parsers them for Autopsy V4"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseWebcacheIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class ParseWebcacheIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseWebcacheIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_Webcache.exe")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("EXE was not found in module folder")

     
    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

 
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "WebcacheV01.dat")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Webcache")
        except:
		    self.log(Level.INFO, "Webcache Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\Webcache", file.getName() + "-" + str(file.getId()))
            DbPath = os.path.join(Temp_Dir, file.getName() + "-" + str(file.getId()) + ".db3")
            self.log(Level.INFO, file.getName() + ' ==> ' + str(file.getId()) + ' ==> ' + file.getUniquePath()) 
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Run the EXE, saving output to a sqlite database
            self.log(Level.INFO, "Running program on data source parm 1 ==> " + Temp_Dir + "  Parm 2 ==> " + Temp_Dir + "\WebcacheV01.db3")
            subprocess.Popen([self.path_to_exe, lclDbPath, DbPath]).communicate()[0]   

        # Example has only a Windows EXE, so bail if we aren't on Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
            return IngestModule.ProcessResult.OK

               
        for file in files:	
           # Open the DB using JDBC
           lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), file.getName() + "-" + str(file.getId()) + ".db3")
           self.log(Level.INFO, "Path the Webcache database file created ==> " + lclDbPath)

           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
            
           #PSlsit => TSK_PROG_RUN
	       #
		
           # Query the contacts table in the database and get all columns. 
           try:
               stmt = dbConn.createStatement()
               resultSet = stmt.executeQuery("Select distinct container_name from all_containers;")
               self.log(Level.INFO, "query SQLite Master table")
           except SQLException as e:
               self.log(Level.INFO, "Error querying database for Prefetch table (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
     
           Container_List = []
           while resultSet.next():
              Container_List.append(resultSet.getString("container_name"))
           #self.log(Level.INFO, "Number of containers ==> " + str(len(Container_List)) + " ==> " + str(Container_List))           
           #self.log(Level.INFO, "Number of containers ==> " + str(Container_List)           

                       
           # Cycle through each row and create artifacts
           for c_name in Container_List:
               try: 
                   container_name = c_name
                   #self.log(Level.INFO, "Result (" + container_name + ")")
                   #self.log(Level.INFO, "Result get information from table " + container_name + " ")
                   SQL_String_1 = "Select * from all_containers where container_name = '" + container_name + "';"
                   SQL_String_2 = "PRAGMA table_info('All_Containers')"
                   #self.log(Level.INFO, SQL_String_1)
                   #self.log(Level.INFO, SQL_String_2)
                   artifact_name = "TSK_WC_" + container_name.upper()
                   artifact_desc = "WebcacheV01 " + container_name.upper()
                   #self.log(Level.INFO, "Artifact Name ==> " + artifact_name + "  Artifact Desc ==> " + artifact_desc)
                   try:
                        self.log(Level.INFO, "Begin Create New Artifacts")
                        artID_web = skCase.addArtifactType( artifact_name, artifact_desc)
                   except:		
                        self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
                   artID_web = skCase.getArtifactTypeID(artifact_name)
                   artID_web_evt = skCase.getArtifactType(artifact_name)
				   
                   Column_Names = []
                   Column_Types = []
                   resultSet2  = stmt.executeQuery(SQL_String_2)
                   while resultSet2.next(): 
                      Column_Names.append(resultSet2.getString("name").upper())
                      Column_Types.append(resultSet2.getString("type").upper())
                      #attID_ex1 = skCase.addAttrType("TSK_" + resultSet2.getString("name").upper(), resultSet2.getString("name"))
                      #self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + str(attID_ex1))
                      #self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + resultSet2.getString("type").upper())
                      if resultSet2.getString("type").upper() == "TEXT":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute. TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                              #self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + str(attID_ex1))
                          except:		
                               self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      elif resultSet2.getString("type").upper() == "":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                              #self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + str(attID_ex1))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      else:
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet2.getString("name"))
                              #self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + str(attID_ex1))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")

										 
                   resultSet3 = stmt.executeQuery(SQL_String_1)
                   while resultSet3.next():
                      art = file.newArtifact(artID_web)
                      Column_Number = 1
                      for col_name in Column_Names:
                         #self.log(Level.INFO, "Result get information for column " + Column_Names[Column_Number - 1] + " ==> " + Column_Types[Column_Number - 1])
                         #self.log(Level.INFO, "Result get information for column_number " + str(Column_Number) + " ")
                         c_name = "TSK_" + col_name
                         #self.log(Level.INFO, "Attribute Name is " + c_name + " ")
                         attID_ex1 = skCase.getAttrTypeID(c_name)
                         attID_ex1 = skCase.getAttributeType(c_name)
                         if Column_Types[Column_Number - 1] == "TEXT":
                             art.addAttribute(BlackboardAttribute(attID_ex1, ParseWebcacheIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                         elif Column_Types[Column_Number - 1] == "":
                              art.addAttribute(BlackboardAttribute(attID_ex1, ParseWebcacheIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
#                             elif Column_Types[Column_Number - 1] == "BLOB":
#                                 art.addAttribute(BlackboardAttribute(attID_ex1, ParseSRUDBIngestModuleFactory.moduleName, "BLOBS Not Supported"))
#                             elif Column_Types[Column_Number - 1] == "REAL":
#                                 art.addAttribute(BlackboardAttribute(attID_ex1, ParseSRUDBIngestModuleFactory.moduleName, resultSet3.getFloat(Column_Number)))
                         else:
                             #self.log(Level.INFO, "Value for column type ==> " + str(resultSet3.getInt(Column_Number)) + " <== ")
                             art.addAttribute(BlackboardAttribute(attID_ex1, ParseWebcacheIngestModuleFactory.moduleName, long(resultSet3.getInt(Column_Number))))
                         Column_Number = Column_Number + 1
                   IngestServices.getInstance().fireModuleDataEvent(
                             ModuleDataEvent(ParseWebcacheIngestModuleFactory.moduleName, artID_web_evt, None))						
               except SQLException as e:
                   self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

        # Clean up
           #stmt.close()
           #dbConn.close()
      
           #os.remove(lclDbPath)
  		
		#Clean up EventLog directory and files
        for file in files:
            try:
                os.remove(Temp_Dir + "\\Webcache\\" + file.getName() + "-" + str(file.getId()))
                os.remove(Temp_Dir + "\\" + file.getName() + "-" + str(file.getId()) + ".db3")
            except:
			    self.log(Level.INFO, "removal of Webcache file failed " + Temp_Dir + "\\" + file.getName() + "-" + str(file.getId()))
        try:
             os.rmdir(Temp_Dir + "\\Webcache")		
        except:
		     self.log(Level.INFO, "removal of Webcache directory failed " + Temp_Dir)

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Webcache Parser", " Webcache Has Been Parsed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
