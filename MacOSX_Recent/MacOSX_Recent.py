# This python autopsy module will export/parse Mac recents.  
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

# MacOSX recent module to parse the Mac OSX recent artifacts.
# February 2017
# 
# Comments 
#   Version 1.0 - Initial version - Feb 2017
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
from org.sleuthkit.datamodel import TskCoreException


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ParseMacOS_RecentIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Parse MACOS Recents"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses Mac OS Recent Artifacts"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseMacOS_RecentIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ParseMacOS_RecentIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseMacOS_RecentIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        #self.local_settings = settings
        self.path_to_safari_exe = ""
        self.artifact_name = ""
        self.os_version = ""
        
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        #self.path_to_safari_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plist_safari.exe")
        #if not os.path.exists(self.path_to_safari_exe):
        #    raise IngestModuleException("plist_safari.exe was not found in module folder")
        
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

        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\Macos_recents.db3"

        # Run this first to get the version of the OS to pass to the rest of the program
        self.parse_plist_data(dataSource, progressBar, 'All', 1, settings_db)
        self.log(Level.INFO, "MacOS Version is ===> " + self.os_version + " < == ")
  
        # get rid of minor revision number
        if self.os_version.count('.') > 1:
           position = 0
           count = 0
           for c in self.os_version:
               position = position + 1
               if c == '.':
                  count = count + 1
               if count > 1:
                  break                   
           self.os_version = self.os_version[:position - 1]           
  
        #Start to process based on version of OS
        try: 
           Class.forName("org.sqlite.JDBC").newInstance()
           dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
           self.log(Level.INFO, "Could not open database file (not SQLite) macos_recents.db3 (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK
        
        # Query the artifact table in the database and get all columns. 
        try:
           stmt = dbConn.createStatement()
           process_data_sql = "select mac_osx_art_id, mac_osx_art_type, os_version from mac_artifact a, os_version b " + \
                               " where a.os_id = b.os_id and b.os_version = '10.12' and mac_osx_art_id > 1;"
           self.log(Level.INFO, process_data_sql)
           resultSet = stmt.executeQuery(process_data_sql)
           self.log(Level.INFO, "query mac_artifact table")
        except SQLException as e:
           self.log(Level.INFO, "Error querying database for mac_artifact (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK

        # Process all the artifacts based on version of the OS   
        while resultSet.next():
           if resultSet.getString("mac_osx_art_type") == "Plist":
               self.parse_plist_data(dataSource, progressBar, resultSet.getString("os_version"), resultSet.getString("mac_osx_art_id"), \
                                     settings_db)
           else:
               self.parse_sqlite_data(dataSource, progressBar, resultSet.getString("os_version"), resultSet.getString("mac_osx_art_id"), \
                                     settings_db)

        self.log(Level.INFO, "MacOS Version is ===> " + self.os_version + " < == ")
        self.log(Level.INFO, "ending process, Just before call to parse_safari_history")
        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Mac OS Recent Artifacts", " Mac OS Recents Artifacts Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

    def parse_plist_data(self, dataSource, progressBar, os_version, mac_os_art_id, settings_db):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        skCase = Case.getCurrentCase().getSleuthkitCase();
        
        try: 
           Class.forName("org.sqlite.JDBC").newInstance()
           dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
           self.log(Level.INFO, "Could not open database file (not SQLite) macos_recents.db3 (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK
        
        # Query the Artifact table in the database and get all columns. 
        try:
           stmt = dbConn.createStatement()
           macos_version_sql = "select mac_osx_art_id, mac_osx_art_type, mac_osx_art_File_Name, mac_osx_art_dir_name, mac_osx_art_exec_file, " + \
                                " mac_osx_art_database_name, mac_osx_art_table_name,  mac_osx_art_sql_statement, os_version, " + \
                                " os_name from mac_artifact a, os_version b where a.os_id = b.os_id and b.os_version = '" + os_version + "'" + \
                                " and mac_osx_art_id = " + str(mac_os_art_id) + ";"
           self.log(Level.INFO, macos_version_sql)
           resultSet = stmt.executeQuery(macos_version_sql)
           self.log(Level.INFO, "query recent version table")
        except SQLException as e:
           self.log(Level.INFO, "Error querying database for recent version (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK

        # get the artifacts to see if they need to be created   
        try:
           stmt_2 = dbConn.createStatement()
           artifact_sql = "select distinct autopsy_art_type, autopsy_art_name, autopsy_art_description " + \
                          " from autopsy_artifact a, Art_att_mac_xref b where a.autopsy_art_id = b.autopsy_art_id " + \
                          " and b.mac_osx_art_id = " + resultSet.getString("mac_osx_art_id") + ";"           
           resultSet_art = stmt_2.executeQuery(artifact_sql)

           self.log(Level.INFO, "Artifact Type (" + resultSet_art.getString("autopsy_art_type") + ")")
           
           if resultSet_art.getString("autopsy_art_type") != 'AUTOPSY':
               try:
                  self.log(Level.INFO, "Begin Create New Artifacts ==> " + resultSet_art.getString("autopsy_art_name"))
                  self.artifact_name = resultSet_art.getString("autopsy_art_name")
                  artID_art = skCase.addArtifactType( resultSet_art.getString("autopsy_art_name"), \
                                                      resultSet_art.getString("autopsy_art_description"))
               except TskCoreException as ex:		
                  self.log(Level.INFO, "Artifacts Creation Error, artifact " + resultSet_art.getString("autopsy_art_name") + " exists. ==> " + str(ex), ex)
           else:
               self.artifact_name = resultSet_art.getString("autopsy_art_name")

           # Get all the attributes to see if they need to be created       
           stmt_3 = dbConn.createStatement()
           attribute_sql = "select distinct autopsy_attrib_type, autopsy_attrib_name, autopsy_attrib_desc, autopsy_attrib_value_type_desc " + \
                          " from autopsy_attribute a, Art_att_mac_xref b, autopsy_value_type c " + \
                          " where a.autopsy_attrib_id = b.autopsy_attrib_id and a.autopsy_attrib_value_type = c.autopsy_attrib_value_type " + \
                          " and b.mac_osx_art_id =" + resultSet.getString("mac_osx_art_id") + ";" 
           self.log(Level.INFO, "Attribute SQL ==> " + attribute_sql)                          
           resultSet_att = stmt_3.executeQuery(attribute_sql)

           while resultSet_att.next():
                if resultSet_att.getString("autopsy_attrib_type")  == 'CUSTOM':
                    if resultSet_att.getString("autopsy_attrib_value_type_desc") == 'String':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    elif resultSet_att.getString("autopsy_attrib_value_type_desc") == 'Integer':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    elif resultSet_att.getString("autopsy_attrib_value_type_desc") == 'Long':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    elif resultSet_att.getString("autopsy_attrib_value_type_desc") == 'Double':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    elif resultSet_att.getString("autopsy_attrib_value_type_desc") == 'Byte':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    else:
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
        except SQLException as e:
           self.log(Level.INFO, "Error querying database for artifacts/attributes (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK
   
        # Cycle through each row and create artifacts
        while resultSet.next():

        # Set the database to be read to the once created by the prefetch parser program
            macos_file_name = resultSet.getString("mac_osx_art_File_Name")
            macos_dir_name = resultSet.getString("mac_osx_art_dir_name")
            macos_database_name = resultSet.getString("mac_osx_art_database_name")
            macos_table_name = resultSet.getString("mac_osx_art_table_name")
            self.path_to_plist_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), resultSet.getString("mac_osx_art_exec_file"))
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            files = fileManager.findFiles(dataSource, macos_file_name, macos_dir_name)
            numFiles = len(files)
            self.log(Level.INFO, "found " + str(numFiles) + " files")
            progressBar.switchToDeterminate(numFiles)
            fileCount = 0;
            all_files = []

            # for file in files:
                # if file.getParentPath() == macos_dir_name + "/":
                   # self.log(Level.INFO, file.getParentPath())
                   # all_files.append(file)
            
            # files = all_files
            
            # Create Event Log directory in temp directory, if it exists then continue on processing		
            Temp_Dir = Case.getCurrentCase().getTempDirectory()
            self.log(Level.INFO, "create Directory " + Temp_Dir)
            try:
                os.mkdir(Temp_Dir + "\macos_recent")
            except:
                self.log(Level.INFO, "macos_recent Directory already exists " + Temp_Dir)
                
            # Write out each Event Log file to the temp directory
            for file in files:
                
                self.log(Level.INFO, str(file))
                
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                #self.log(Level.INFO, "Processing file: " + file.getName())
                fileCount += 1

                # Save the DB locally in the temp folder. use file id as name to reduce collisions
                lclDbPath = os.path.join(Temp_Dir + "\macos_recent", file.getName())
                ContentUtils.writeToFile(file, File(lclDbPath))

                lclDbPath = os.path.join(Temp_Dir + "\macos_recent", macos_database_name)
                lclFilePath = os.path.join(Temp_Dir + "\macos_recent", macos_file_name)

                self.log(Level.INFO, "Running prog ==> " + self.path_to_plist_exe + " " + lclFilePath + " " + \
                                     lclDbPath + " " + macos_table_name)
                pipe = Popen([self.path_to_plist_exe, lclFilePath, lclDbPath, macos_table_name], stdout=PIPE, stderr=PIPE)
                
                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text) 
            
            for file in files:
               
                # Example has only a Windows EXE, so bail if we aren't on Windows
                if not PlatformUtil.isWindowsOS(): 
                    self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
                    return IngestModule.ProcessResult.OK

                # Open the DB using JDBC
                lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory() + "\macos_recent", macos_database_name)
                self.log(Level.INFO, "Path the Safari History.db database file created ==> " + lclDbPath)
                try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
                
                # Query the history_visits table in the database and get all columns. 
                try:
                   stmt_1 = dbConn.createStatement()
                   macos_recent_sql = resultSet.getString("mac_osx_art_sql_statement")
                   self.log(Level.INFO, macos_recent_sql)
                   resultSet_3 = stmt_1.executeQuery(macos_recent_sql)
                   self.log(Level.INFO, "query " + macos_database_name + " table")
                except SQLException as e:
                   self.log(Level.INFO, "Error querying database for history table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

                artID_hst = skCase.getArtifactTypeID(self.artifact_name)
                artID_hst_evt = skCase.getArtifactType(self.artifact_name)

                meta = resultSet_3.getMetaData()
                columncount = meta.getColumnCount()
                column_names = []
                self.log(Level.INFO, "Number of Columns in the table ==> " + str(columncount))
                for x in range (1, columncount + 1):
                    self.log(Level.INFO, "Column Name ==> " + meta.getColumnLabel(x))
                    column_names.append(meta.getColumnLabel(x))
                
                self.log(Level.INFO, "All Columns ==> " + str(column_names))
                # Cycle through each row and create artifacts
                while resultSet_3.next():
                   try: 
                       #self.log(Level.INFO, SQL_String_1)
                       self.log(Level.INFO, "Artifact Is ==> " + str(artID_hst))
                       
                       art = file.newArtifact(artID_hst)
                       self.log(Level.INFO, "Inserting attribute URL")
                       for col_name in column_names:
                           if ((col_name == "TSK_VERSION") and (mac_os_art_id == 1)):
                               self.os_version = resultSet_3.getString(col_name)
                           attID_ex1 = skCase.getAttributeType(col_name)
                           self.log(Level.INFO, "Inserting attribute ==> " + str(attID_ex1))
                           self.log(Level.INFO, "Attribute Type ==> " + str(attID_ex1.getValueType()))
                           if attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getString(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes String Creation Error, " + col_name + " ==> ")
                           elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Integer Creation Error, " + col_name + " ==> ")
                           elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Long Creation Error, " + col_name + " ==> ")
                           elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Double Creation Error, " + col_name + " ==> ")
                           elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getString(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Byte Creation Error, " + col_name + " ==> ")
                           else:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getReal(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Datatime Creation Error, " + col_name + " ==> ")

                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from web_history table (" + e.getMessage() + ")")

                IngestServices.getInstance().fireModuleDataEvent(
                       ModuleDataEvent(ParseMacOS_RecentIngestModuleFactory.moduleName, artID_hst_evt, None))

                stmt_3.close()
                stmt_2.close()
                stmt_1.close()
                stmt.close()
                dbConn.close()

                # Clean up
                os.remove(lclDbPath)
                os.remove(lclFilePath)
                        
            #Clean up EventLog directory and files
            for file in files:
               try:
                  os.remove(Temp_Dir + "\\macos_recent\\" + file.getName())
               except:
                  self.log(Level.INFO, "removal of Safari History file failed " + Temp_Dir + "\\macos_recent" + file.getName())
            try:
               os.rmdir(Temp_Dir + "\\macos_recent")		
            except:
               self.log(Level.INFO, "removal of Safari History directory failed " + Temp_Dir)
       
    def parse_sqlite_data(self, dataSource, progressBar, os_version, mac_os_art_id, settings_db):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        skCase = Case.getCurrentCase().getSleuthkitCase();
        
        try: 
           Class.forName("org.sqlite.JDBC").newInstance()
           dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
           self.log(Level.INFO, "Could not open database file (not SQLite) macos_recents.db3 (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK
        
        # Query the history_visits table in the database and get all columns. 
        try:
           stmt = dbConn.createStatement()
           macos_version_sql = "select mac_osx_art_id, mac_osx_art_type, mac_osx_art_File_Name, mac_osx_art_dir_name, " + \
                                " mac_osx_art_database_name, mac_osx_art_sql_statement, os_version, " + \
                                " os_name from mac_artifact a, os_version b where a.os_id = b.os_id and b.os_version = '" + os_version + "'" + \
                                " and mac_osx_art_id = " + str(mac_os_art_id) + ";"
           self.log(Level.INFO, macos_version_sql)
           resultSet = stmt.executeQuery(macos_version_sql)
           self.log(Level.INFO, "query recent version table")
        except SQLException as e:
           self.log(Level.INFO, "Error querying database for recent version (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK
  
        # Get the artifact name and create it.
        try:
           stmt_2 = dbConn.createStatement()
           artifact_sql = "select distinct autopsy_art_type, autopsy_art_name, autopsy_art_description " + \
                          " from autopsy_artifact a, Art_att_mac_xref b where a.autopsy_art_id = b.autopsy_art_id " + \
                          " and b.mac_osx_art_id = " + resultSet.getString("mac_osx_art_id") + ";"           
           resultSet_art = stmt_2.executeQuery(artifact_sql)

           self.log(Level.INFO, "Artifact Type (" + resultSet_art.getString("autopsy_art_type") + ")")
           
           if resultSet_art.getString("autopsy_art_type") != 'AUTOPSY':
               try:
                  self.log(Level.INFO, "Begin Create New Artifacts ==> " + resultSet_art.getString("autopsy_art_name"))
                  artID_art = skCase.addArtifactType( resultSet_art.getString("autopsy_art_name"), \
                                                      resultSet_art.getString("autopsy_art_desctiption"))
                  self.artifact_name = resultSet_art.getString("autopsy_art_name")
               except:		
                  self.log(Level.INFO, "Artifacts Creation Error, artifact " + resultSet_art.getString("autopsy_art_name") + " exists. ==> ")
           else:
               self.artifact_name = resultSet_art.getString("autopsy_art_name")

           # Get the attribute types and create them       
           stmt_3 = dbConn.createStatement()
           attribute_sql = "select distinct autopsy_attrib_type, autopsy_attrib_name, autopsy_attrib_desc, autopsy_attrib_value_type_desc " + \
                          " from autopsy_attribute a, Art_att_mac_xref b, autopsy_value_type c " + \
                          " where a.autopsy_attrib_id = b.autopsy_attrib_id and a.autopsy_attrib_value_type = c.autopsy_attrib_value_type " + \
                          " and b.mac_osx_art_id =" + resultSet.getString("mac_osx_art_id") + ";" 
           self.log(Level.INFO, "Attribute SQL ==> " + attribute_sql)                          
           resultSet_att = stmt_3.executeQuery(attribute_sql)

           while resultSet_att.next():
               if resultSet_att.getString("autopsy_attrib_type")  == 'CUSTOM':
                    if resultSet_att.getString("autopsy_attrib_value_type_desc") == 'String':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    elif resultSet_att.getString("autopsy_attrib_value_type_desc") == 'Integer':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    elif resultSet_att.getString("autopsy_attrib_value_type_desc") == 'Long':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    elif resultSet_att.getString("autopsy_attrib_value_type_desc") == 'Double':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    elif resultSet_att.getString("autopsy_attrib_value_type_desc") == 'Byte':
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
                    else:
                        try:
                           attID_vss_num = skCase.addArtifactAttributeType(resultSet_att.getString("autopsy_attrib_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, resultSet_att.getString("autopsy_attrib_desc"))
                        except:		
                           self.log(Level.INFO, "Attributes Creation Error for ," +  resultSet_att.getString("autopsy_attrib_name") + " ==> ")
        except SQLException as e:
           self.log(Level.INFO, "Error querying database for artifacts/attributes (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK
   
        # Cycle through each row and create artifacts
        while resultSet.next():

        # Set the database to be read to the once created by the prefetch parser program
            macos_file_name = resultSet.getString("mac_osx_art_File_Name")
            macos_dir_name = resultSet.getString("mac_osx_art_dir_name")
            macos_database_name = resultSet.getString("mac_osx_art_database_name")
            #macos_table_name = resultSet.getString("mac_osx_art_table_name")
            #self.path_to_plist_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), resultSet.getString("mac_osx_art_exec_file"))
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            files = fileManager.findFiles(dataSource, macos_file_name + "%", macos_dir_name)
            numFiles = len(files)
            self.log(Level.INFO, "found " + str(numFiles) + " files")
            progressBar.switchToDeterminate(numFiles)
            fileCount = 0;
            all_files = []

            # do this since we want to get the wal or journal files associated with the SQLite database but we want to 
            # make sure we have them to use
            if numFiles > 1:
                for file in files:
                    if file.getName() == macos_file_name:
                       self.log(Level.INFO, file.getParentPath())
                       all_files.append(file)
             
            files_to_process = all_files
            
            # Create Event Log directory in temp directory, if it exists then continue on processing		
            Temp_Dir = Case.getCurrentCase().getTempDirectory()
            self.log(Level.INFO, "create Directory " + Temp_Dir)
            try:
                os.mkdir(Temp_Dir + "\macos_recent")
            except:
                self.log(Level.INFO, "macos_recent Directory already exists " + Temp_Dir)
                
            # Write out each Event Log file to the temp directory
            file_id = 0
            for file in files:
                
                #self.log(Level.INFO, str(file))
                
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                #self.log(Level.INFO, "Processing file: " + file.getName())
                fileCount += 1

                # Save the DB locally in the temp folder. use file id as name to reduce collisions, also add file id to wal and journal files
                # if needed so that it can use the journals.
                self.log(Level.INFO, "File Name ==> " + file.getName() + " <==> " + macos_database_name)
                if file.getName().upper() == macos_database_name.upper():
                    file_id = file.getId()
                    self.log(Level.INFO, "File Name ==> " + file.getName() + " <==> " + macos_database_name + " <++> " + str(file.getId()))
                    lclDbPath = os.path.join(Temp_Dir + "\macos_recent", str(file_id) + "-" + file.getName())
                    self.log(Level.INFO, " Database name ==> " + lclDbPath)
                    ContentUtils.writeToFile(file, File(lclDbPath))
                else:
                    lclDbPath = os.path.join(Temp_Dir + "\macos_recent", str(file_id) + "-" + file.getName())
                    self.log(Level.INFO, " Database name ==> " + lclDbPath)
                    ContentUtils.writeToFile(file, File(lclDbPath))
                    

                lclDbPath = os.path.join(Temp_Dir + "\macos_recent", str(file_id) + "-" + macos_database_name)
                lclFilePath = os.path.join(Temp_Dir + "\macos_recent", macos_file_name)
                self.log(Level.INFO, " Database name ==> " + lclDbPath + " File Path ==> " + lclFilePath)
            
            for file in files_to_process:
               
                # Example has only a Windows EXE, so bail if we aren't on Windows
                if not PlatformUtil.isWindowsOS(): 
                    self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
                    return IngestModule.ProcessResult.OK

                # Open the DB using JDBC
                lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory() + "\macos_recent", str(file.getId()) + "-" + macos_database_name)
                self.log(Level.INFO, "Path the Safari History.db database file created ==> " + lclDbPath)
                try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
                
                # Query the history_visits table in the database and get all columns. 
                try:
                   stmt_1 = dbConn.createStatement()
                   macos_recent_sql = resultSet.getString("mac_osx_art_sql_statement")
                   self.log(Level.INFO, macos_recent_sql)
                   resultSet_3 = stmt_1.executeQuery(macos_recent_sql)
                   self.log(Level.INFO, "query " + macos_database_name + " table")
                except SQLException as e:
                   self.log(Level.INFO, "Error querying database for history table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

                artID_hst = skCase.getArtifactTypeID(self.artifact_name)
                artID_hst_evt = skCase.getArtifactType(self.artifact_name)

                meta = resultSet_3.getMetaData()
                columncount = meta.getColumnCount()
                column_names = []
                self.log(Level.INFO, "Number of Columns in the table ==> " + str(columncount))
                for x in range (1, columncount + 1):
                    self.log(Level.INFO, "Column Name ==> " + meta.getColumnLabel(x))
                    column_names.append(meta.getColumnLabel(x))
                
                self.log(Level.INFO, "All Columns ==> " + str(column_names))
                # Cycle through each row and create artifacts
                while resultSet_3.next():
                   try: 
                       #self.log(Level.INFO, SQL_String_1)
                       self.log(Level.INFO, "Artifact Is ==> " + str(artID_hst))
                       
                       art = file.newArtifact(artID_hst)
                       self.log(Level.INFO, "Inserting attribute URL")
                       for col_name in column_names:
                           attID_ex1 = skCase.getAttributeType(col_name)
                           self.log(Level.INFO, "Inserting attribute ==> " + str(attID_ex1))
                           self.log(Level.INFO, "Attribute Type ==> " + str(attID_ex1.getValueType()))
                           if attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getString(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes String Creation Error, " + col_name + " ==> ")
                           elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Integer Creation Error, " + col_name + " ==> ")
                           elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Long Creation Error, " + col_name + " ==> ")
                           elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Double Creation Error, " + col_name + " ==> ")
                           elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getString(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Byte Creation Error, " + col_name + " ==> ")
                           else:
                                try:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, ParseMacOS_RecentIngestModuleFactory.moduleName, resultSet_3.getReal(col_name)))
                                except:		
                                    self.log(Level.INFO, "Attributes Datatime Creation Error, " + col_name + " ==> ")

                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from web_history table (" + e.getMessage() + ")")

                IngestServices.getInstance().fireModuleDataEvent(
                       ModuleDataEvent(ParseMacOS_RecentIngestModuleFactory.moduleName, artID_hst_evt, None))

                stmt_3.close()
                stmt_2.close()
                stmt_1.close()
                stmt.close()
                dbConn.close()

                # Clean up
                os.remove(lclDbPath)
                        
            #Clean up EventLog directory and files
            for file in files:
               try:
                  os.remove(Temp_Dir + "\\macos_recent\\" + file.getName())
               except:
                  self.log(Level.INFO, "removal of Safari History file failed " + Temp_Dir + "\\macos_recent" + file.getName())
            try:
               os.rmdir(Temp_Dir + "\\macos_recent")		
            except:
               self.log(Level.INFO, "removal of Safari History directory failed " + Temp_Dir)
       
       