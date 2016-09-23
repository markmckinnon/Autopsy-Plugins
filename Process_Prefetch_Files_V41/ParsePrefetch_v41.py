# This python autopsy module will export the prefetch files and then call
# the command line version of the prefetch_parser.  A sqlite database that
# contains the prefetch information is created then imported into the extracted
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

# Prefetch Parser module to parse the prefetch folder from windows.
# September 2015
# 
# Comments 
#   Version 1.0 - Initial version - September 2015
#   Version 1.1 - Fixed incorrect source file being displayed - October 16, 2015
#   Version 1.2 - Made changes to add custom artifacts - July 22, 2016
#   Version 1.3 - Made changes to add custom artifacts/attributes - August 29 2016
# 

import jarray
import inspect
import os
import subprocess
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
class ParsePrefetchDbIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "ParsePrefetchV41"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Sample module that parses the Copies the prefetch files and parsers them for Autopsy V4"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParsePrefetchDbIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class ParsePrefetchDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParsePrefetchDbIngestModuleFactory.moduleName)

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
        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Prefetch_Parser_Autopsy.exe")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("EXE was not found in module folder")
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # Check to see if the artifacts exist and if not then create it, also check to see if the attributes
		# exist and if not then create them
        skCase = Case.getCurrentCase().getSleuthkitCase();
        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_pf = skCase.addArtifactType( "TSK_PREFETCH", "Windows Prefetch")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_pf = skCase.getArtifactTypeID("TSK_PREFETCH")
             
        # Create the attribute type, if it exists then catch the error
        try:
            attID_pf_fn = skCase.addArtifactAttributeType("TSK_PREFETCH_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Prefetch File Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Prefetch File Name. ==> ")

        try:
            attID_pf_an = skCase.addArtifactAttributeType("TSK_PREFETCH_ACTUAL_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Actual File Name")			 
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Actual File Name. ==> ")

        try:
            attID_nr = skCase.addArtifactAttributeType("TSK_PF_RUN_COUNT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Program Number Runs")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Program Number Runs. ==> ")

        try:
            attID_ex1 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_1", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PF Execution DTTM 1")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 1. ==> ")

        try:
            attID_ex2 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_2", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PF Execution DTTM 2")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 2. ==> ")

        try:
            attID_ex3 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_3", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PF Execution DTTM 3")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 3. ==> ")

        try:
            attID_ex4 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_4", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PF Execution DTTM 4")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 4 ==> ")

        try:
            attID_ex5 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_5", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PF Execution DTTM 5")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 5. ==> ")

        try:
            attID_ex6 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_6", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PF Execution DTTM 6")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 6. ==> ")

        try:
            attID_ex7 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_7", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PF Execution DTTM 7")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 7. ==> ")

        try:
            attID_ex8 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_8", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PF Execution DTTM 8")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 8 ==> ")

        self.log(Level.INFO, "Get Artifacts after they were created.")
        # Get the new artifacts and attributes that were just created
        artID_pf = skCase.getArtifactTypeID("TSK_PREFETCH")
        artID_pf_evt = skCase.getArtifactType("TSK_PREFETCH")
        attID_pf_fn = skCase.getAttributeType("TSK_PREFETCH_FILE_NAME")
        attID_pf_an = skCase.getAttributeType("TSK_PREFETCH_ACTUAL_FILE_NAME")
        attID_nr = skCase.getAttributeType("TSK_PF_RUN_COUNT")
        attID_ex1 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_1")
        attID_ex2 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_2")
        attID_ex3 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_3")
        attID_ex4 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_4")
        attID_ex5 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_5")
        attID_ex6 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_6")
        attID_ex7 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_7")
        attID_ex8 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_8")

        # Uncomment for debugging purposes, not normally needed
        # self.log(Level.INFO, "Artifact id for TSK_PREFETCH ==> " + str(artID_pf))
        # self.log(Level.INFO, "Attribute id for TSK_PREFETCH_FILE_NAME ==> " + str(attID_pf_fn))
        # self.log(Level.INFO, "Attribute id for TSK_PREFETCH_ACTUAL_FILE_NAME ==> " + str(attID_pf_an))
        # self.log(Level.INFO, "Attribute id for TSK_PF_RUN_COUNT ==> " + str(attID_nr))
        # self.log(Level.INFO, "Attribute id for TSK_PF_EXEC_DTTM_1 ==> " + str(attID_ex1))
        # self.log(Level.INFO, "Attribute id for TSK_PF_EXEC_DTTM_2 ==> " + str(attID_ex2))
        # self.log(Level.INFO, "Attribute id for TSK_PF_EXEC_DTTM_3 ==> " + str(attID_ex3))
        # self.log(Level.INFO, "Attribute id for TSK_PF_EXEC_DTTM_4 ==> " + str(attID_ex4))
        # self.log(Level.INFO, "Attribute id for TSK_PF_EXEC_DTTM_5 ==> " + str(attID_ex5))
        # self.log(Level.INFO, "Attribute id for TSK_PF_EXEC_DTTM_6 ==> " + str(attID_ex6))
        # self.log(Level.INFO, "Attribute id for TSK_PF_EXEC_DTTM_7 ==> " + str(attID_ex7))
        # self.log(Level.INFO, "Attribute id for TSK_PF_EXEC_DTTM_8 ==> " + str(attID_ex8))

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Find the prefetch files and the layout.ini file from the /windows/prefetch folder
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.pf")
        
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
		
        # Create prefetch directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory() + "\Prefetch_Files"
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "Prefetch Directory already exists " + Temp_Dir)
			
        # Write out each prefetch file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir, file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        

        # Example has only a Windows EXE, so bail if we aren't on Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
            return IngestModule.ProcessResult.OK

        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on data source parm 1 ==> " + Temp_Dir + "  Parm 2 ==> " + Case.getCurrentCase().getTempDirectory())
        subprocess.Popen([self.path_to_exe, Temp_Dir, Case.getCurrentCase().getTempDirectory()]).communicate()[0]   
			
        # Set the database to be read to the once created by the prefetch parser program
        lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "Autopsy_PF_DB.db3")
        self.log(Level.INFO, "Path the prefetch database file created ==> " + lclDbPath)
                        
        # Open the DB using JDBC
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
            
        # Query the contacts table in the database and get all columns. 
        try:
            stmt = dbConn.createStatement()
            resultSet = stmt.executeQuery("Select prefetch_File_Name, actual_File_Name, Number_time_file_run, " +
                                          " Embeded_date_Time_Unix_1, " +
                                          " Embeded_date_Time_Unix_2, " +
                                          " Embeded_date_Time_Unix_3, " +
                                          " Embeded_date_Time_Unix_4, " +
                                          " Embeded_date_Time_Unix_5, " +
                                          " Embeded_date_Time_Unix_6, " +   
                                          " Embeded_date_Time_Unix_7, " +       
                                          " Embeded_date_Time_Unix_8 " +
                                          " from prefetch_file_info ")
        except SQLException as e:
            self.log(Level.INFO, "Error querying database for Prefetch table (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK

        # Cycle through each row and create artifacts
        while resultSet.next():
            try: 
                self.log(Level.INFO, "Result (" + resultSet.getString("Prefetch_File_Name") + ")")
                Prefetch_File_Name  = resultSet.getString("Prefetch_File_Name")
                Actual_File_Name = resultSet.getString("Actual_File_Name")
                Number_Of_Runs = resultSet.getString("Number_Time_File_Run")
                Time_1 = resultSet.getString("Embeded_date_Time_Unix_1")
                Time_2 = resultSet.getString("Embeded_date_Time_Unix_2")
                Time_3 = resultSet.getString("Embeded_date_Time_Unix_3")
                Time_4 = resultSet.getString("Embeded_date_Time_Unix_4")
                Time_5 = resultSet.getString("Embeded_date_Time_Unix_5")
                Time_6 = resultSet.getString("Embeded_date_Time_Unix_6")
                Time_7 = resultSet.getString("Embeded_date_Time_Unix_7")
                Time_8 = resultSet.getString("Embeded_date_Time_Unix_8")
            except SQLException as e:
                self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

            fileManager = Case.getCurrentCase().getServices().getFileManager()
            files = fileManager.findFiles(dataSource, Prefetch_File_Name)                
            
            for file in files:
                # Make artifact for TSK_PREFETCH,  this can happen when custom attributes are fully supported
                #art = file.newArtifact(artID_pf)
                art = file.newArtifact(artID_pf)

                #self.log(Level.INFO, "Attribute Number ==>" + str(attID_pf_fn) + " " + str(attID_pf_an) )
                # Add the attributes to the artifact.
                art.addAttributes(((BlackboardAttribute(attID_pf_fn, ParsePrefetchDbIngestModuleFactory.moduleName, Prefetch_File_Name)), \
                                  (BlackboardAttribute(attID_pf_an, ParsePrefetchDbIngestModuleFactory.moduleName, Actual_File_Name)), \
                                  (BlackboardAttribute(attID_nr, ParsePrefetchDbIngestModuleFactory.moduleName, Number_Of_Runs)), \
                                  (BlackboardAttribute(attID_ex1, ParsePrefetchDbIngestModuleFactory.moduleName, Time_1)), \
                                  (BlackboardAttribute(attID_ex2, ParsePrefetchDbIngestModuleFactory.moduleName, Time_2)), \
                                  (BlackboardAttribute(attID_ex3, ParsePrefetchDbIngestModuleFactory.moduleName, Time_3)), \
                                  (BlackboardAttribute(attID_ex4, ParsePrefetchDbIngestModuleFactory.moduleName, Time_4)), \
                                  (BlackboardAttribute(attID_ex5, ParsePrefetchDbIngestModuleFactory.moduleName, Time_5)), \
                                  (BlackboardAttribute(attID_ex6, ParsePrefetchDbIngestModuleFactory.moduleName, Time_6)), \
                                  (BlackboardAttribute(attID_ex7, ParsePrefetchDbIngestModuleFactory.moduleName, Time_7)), \
                                  (BlackboardAttribute(attID_ex8, ParsePrefetchDbIngestModuleFactory.moduleName, Time_8))))
			
        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(ParsePrefetchDbIngestModuleFactory.moduleName, artID_pf_evt, None))
                
        # Clean up
        stmt.close()
        dbConn.close()
        os.remove(lclDbPath)

			
		#Clean up prefetch directory and files
        for file in files:
            try:
			    os.remove(Temp_Dir + "\\" + file.getName())
            except:
			    self.log(Level.INFO, "removal of prefetch file failed " + Temp_Dir + "\\" + file.getName())
        try:
             os.rmdir(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of prefetch directory failed " + Temp_Dir)
            
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Prefetch Analyzer", " Prefetch Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(ParsePrefetchDbIngestModuleFactory.moduleName, artID_pf_evt, None))
        
        return IngestModule.ProcessResult.OK