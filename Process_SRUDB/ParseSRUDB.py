# This python autopsy module will export the System Resource Usage Database and then call
# the command line version of the Export_SRUDB program.  A sqlite database that
# contains the Resource Usage information is created then imported into the extracted
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

# SRYDB module to parse the System Resource Usage Database.
# March 2016
# 
# Comments 
#   Version 1.0 - Initial version - APril 2016
#   Version 1.1 - Custom artifacts/attributes - August 31, 2016
#   Version 1.2 - Add Linux support - Oct 2018
# 

import jarray
import inspect
import os
import subprocess

from javax.swing import JCheckBox
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import BoxLayout
from java.awt import GridLayout
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JScrollPane
from javax.swing import JComponent
from java.awt.event import KeyListener


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
class ParseSRUDBIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Parse SRUDB"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses sytem Resource DB"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return Parse_SRUDBWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, Parse_SRUDBWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return Parse_SRUDBWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseSRUDBIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ParseSRUDBIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseSRUDBIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_SRUDB = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        if PlatformUtil.isWindowsOS():
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_SRUDB.exe")
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("EXE was not found in module folder")
        else:
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Export_SRUDB")
            if not os.path.exists(self.path_to_exe):
                raise IngestModuleException("Linux Executable was not found in module folder")

        if self.local_settings.getFlag():
            self.List_Of_SRUDB.append('application_resource_usage')
            self.List_Of_SRUDB.append('energy_estimation_provider')
            self.List_Of_SRUDB.append('energy_usage_data')
            self.List_Of_SRUDB.append('network_connectivity')
            self.List_Of_SRUDB.append('network_usage')
            self.List_Of_SRUDB.append('windows_push_notification')
            #self.logger.logp(Level.INFO, Parse_SRUDBWithUI.__name__, "startUp", "All Events CHecked")
        else:
            #self.logger.logp(Level.INFO, Parse_SRUDBWithUI.__name__, "startUp", "No Boxes Checked")
            if self.local_settings.getFlag1():
                self.List_Of_SRUDB.append('application_resource_usage')
            if self.local_settings.getFlag2():
                self.List_Of_SRUDB.append('energy_estimation_provider')
            if self.local_settings.getFlag3():
                self.List_Of_SRUDB.append('energy_usage_data')
            if self.local_settings.getFlag4():
                self.List_Of_SRUDB.append('network_connectivity')
            if self.local_settings.getFlag5():
                self.List_Of_SRUDB.append('network_usage')
            if self.local_settings.getFlag6():
                self.List_Of_SRUDB.append('windows_push_notification')
        
        #self.logger.logp(Level.INFO, Parse_SRUDBWithUI.__name__, "startUp", str(self.List_Of_Events))
        self.log(Level.INFO, str(self.List_Of_SRUDB))
		
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
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "SRUDB.DAT")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
	    temp_dir = os.path.join(Temp_Dir, "SRUDB")
            os.mkdir(temp_dir)
        except:
	    self.log(Level.INFO, "SRUDB Directory already exists " + Temp_Dir)
	
        temp_file = ""		
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(temp_dir, file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
            temp_file = lclDbPath

        # Run the executable, saving output to a sqlite database
        
        self.log(Level.INFO, "Running program on data source parm 1 ==> " + self.path_to_exe + " == > " + temp_file + "  Parm 2 ==> " + Temp_Dir + "\SRUDB.db3")
        subprocess.Popen([self.path_to_exe, temp_file, os.path.join(Temp_Dir,"SRUDB.db3")]).communicate()[0]   
               
        for file in files:	
           # Open the DB using JDBC
           lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "SRUDB.db3")
           self.log(Level.INFO, "Path the SRUDB database file created ==> " + lclDbPath)
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
            
           #PSlsit => TSK_PROG_RUN
	       #
		
           # Query the contacts table in the database and get all columns. 
           for SR_table_name in self.List_Of_SRUDB:
               try:
                   stmt = dbConn.createStatement()
                   resultSet = stmt.executeQuery("Select tbl_name from SQLITE_MASTER where lower(tbl_name) in ('" + SR_table_name + "'); ")
                   self.log(Level.INFO, "query SQLite Master table")
               except SQLException as e:
                   self.log(Level.INFO, "Error querying database for Prefetch table (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK

               # Cycle through each row and create artifacts
               while resultSet.next():
                   try: 
                       self.log(Level.INFO, "Result (" + resultSet.getString("tbl_name") + ")")
                       table_name = resultSet.getString("tbl_name")
                       self.log(Level.INFO, "Result get information from table " + resultSet.getString("tbl_name") + " ")
                       SQL_String_1 = "Select * from " + table_name + ";"
                       SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
                       #self.log(Level.INFO, SQL_String_1)
                       #self.log(Level.INFO, SQL_String_2)
                       artifact_name = "TSK_" + table_name.upper()
                       artifact_desc = "System Resource Usage " + table_name.upper()
                       try:
                            self.log(Level.INFO, "Begin Create New Artifacts")
                            artID_amc = skCase.addArtifactType( artifact_name, artifact_desc)
                       except:		
                            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

                       artID_sru = skCase.getArtifactTypeID(artifact_name)
                       artID_sru_evt = skCase.getArtifactType(artifact_name)
                       
                       Column_Names = []
                       Column_Types = []
                       resultSet2  = stmt.executeQuery(SQL_String_2)
                       while resultSet2.next(): 
                          Column_Names.append(resultSet2.getString("name").upper())
                          Column_Types.append(resultSet2.getString("type").upper())
                          #attID_ex1 = skCase.addAttrType("TSK_" + resultSet2.getString("name").upper(), resultSet2.getString("name"))
                          #self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + str(attID_ex1))
                          if resultSet2.getString("type").upper() == "TEXT":
                              try:
                                  attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
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
                          art = file.newArtifact(artID_sru)
                          Column_Number = 1
                          for col_name in Column_Names:
                             self.log(Level.INFO, "Result get information for column " + Column_Names[Column_Number - 1] + " ")
                             self.log(Level.INFO, "Result get information for column_number " + str(Column_Number) + " ")
                             c_name = "TSK_" + col_name
                             self.log(Level.INFO, "Attribute Name is " + c_name + " ")
                             attID_ex1 = skCase.getAttributeType(c_name)
                             if Column_Types[Column_Number - 1] == "TEXT":
                                 art.addAttribute(BlackboardAttribute(attID_ex1, ParseSRUDBIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                             elif Column_Types[Column_Number - 1] == "":
                                  art.addAttribute(BlackboardAttribute(attID_ex1, ParseSRUDBIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
#                             elif Column_Types[Column_Number - 1] == "BLOB":
#                                 art.addAttribute(BlackboardAttribute(attID_ex1, ParseSRUDBIngestModuleFactory.moduleName, "BLOBS Not Supported"))
#                             elif Column_Types[Column_Number - 1] == "REAL":
#                                 art.addAttribute(BlackboardAttribute(attID_ex1, ParseSRUDBIngestModuleFactory.moduleName, resultSet3.getFloat(Column_Number)))
                             else:
                                 #self.log(Level.INFO, "Value for column type ==> " + str(resultSet3.getInt(Column_Number)) + " <== ")
                                 art.addAttribute(BlackboardAttribute(attID_ex1, ParseSRUDBIngestModuleFactory.moduleName, long(resultSet3.getInt(Column_Number))))
                             Column_Number = Column_Number + 1

                       IngestServices.getInstance().fireModuleDataEvent(
                             ModuleDataEvent(ParseSRUDBIngestModuleFactory.moduleName, artID_sru_evt, None))
                   except SQLException as e:
                       self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

        # Clean up
        os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        for file in files:
            try:
			    os.remove(temp_file)
            except:
			    self.log(Level.INFO, "removal of SRUDB file failed " + Temp_Dir + "\\" + file.getName())
        try:
             os.rmdir(temp_dir)		
        except:
		     self.log(Level.INFO, "removal of SRUDB directory failed " + Temp_Dir)

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "System Resourse Usage DB", " SRUDB Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class Parse_SRUDBWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.flag = False
        self.flag1 = False
        self.flag2 = False
        self.flag3 = False
        self.flag4 = False
        self.flag5 = False
        self.flag6 = False

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def getFlag(self):
        return self.flag

    def setFlag(self, flag):
        self.flag = flag

    def getFlag1(self):
        return self.flag1

    def setFlag1(self, flag1):
        self.flag1 = flag1

    def getFlag2(self):
        return self.flag2

    def setFlag2(self, flag2):
        self.flag2 = flag2

    def getFlag3(self):
        return self.flag3

    def setFlag3(self, flag3):
        self.flag3 = flag3

    def getFlag4(self):
        return self.flag4

    def setFlag4(self, flag4):
        self.flag4 = flag4

    def getFlag5(self):
        return self.flag5

    def setFlag5(self, flag5):
        self.flag5 = flag5

    def getFlag6(self):
        return self.flag6

    def setFlag6(self, flag6):
        self.flag6 = flag6

    def getArea(self):
        return self.area

    def setArea(self, area):
        self.area = area

# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class Parse_SRUDBWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'
    
    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    # TODO: Update this for your UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()
    
    # TODO: Update this for your UI
    def checkBoxEvent(self, event):
        if self.checkbox.isSelected():
            self.local_settings.setFlag(True)
        else:
            self.local_settings.setFlag(False)

        if self.checkbox1.isSelected():
            self.local_settings.setFlag1(True)
        else:
            self.local_settings.setFlag1(False)

        if self.checkbox2.isSelected():
            self.local_settings.setFlag2(True)
        else:
            self.local_settings.setFlag2(False)

        if self.checkbox3.isSelected():
            self.local_settings.setFlag3(True)
        else:
            self.local_settings.setFlag3(False)

        if self.checkbox4.isSelected():
            self.local_settings.setFlag4(True)
        else:
            self.local_settings.setFlag4(False)

        if self.checkbox5.isSelected():
            self.local_settings.setFlag5(True)
        else:
            self.local_settings.setFlag5(False)

        if self.checkbox5.isSelected():
            self.local_settings.setFlag5(True)
        else:
            self.local_settings.setFlag5(False)

    def keyPressed(self, event):
        self.local_settings.setArea(self.area.getText());

    # TODO: Update this for your UI
    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        #self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.panel1 = JPanel()
        self.panel1.setLayout(BoxLayout(self.panel1, BoxLayout.Y_AXIS))
        self.panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.checkbox = JCheckBox("All Logs", actionPerformed=self.checkBoxEvent)
        self.checkbox1 = JCheckBox("Application Resource Usage", actionPerformed=self.checkBoxEvent)
        self.checkbox2 = JCheckBox("Energy Estimation Provider", actionPerformed=self.checkBoxEvent)
        self.checkbox3 = JCheckBox("Energy Usage Data", actionPerformed=self.checkBoxEvent)
        self.checkbox4 = JCheckBox("Network Connectivity", actionPerformed=self.checkBoxEvent)
        self.checkbox5 = JCheckBox("Network Usage", actionPerformed=self.checkBoxEvent)
        self.checkbox6 = JCheckBox("Windows Push Notification", actionPerformed=self.checkBoxEvent)
        self.panel1.add(self.checkbox)
        self.panel1.add(self.checkbox1)
        self.panel1.add(self.checkbox2)
        self.panel1.add(self.checkbox3)
        self.panel1.add(self.checkbox4)
        self.panel1.add(self.checkbox5)
        self.panel1.add(self.checkbox6)
        self.add(self.panel1)
		
    # TODO: Update this for your UI
    def customizeComponents(self):
        self.checkbox.setSelected(self.local_settings.getFlag())
        self.checkbox1.setSelected(self.local_settings.getFlag1())
        self.checkbox2.setSelected(self.local_settings.getFlag2())
        self.checkbox3.setSelected(self.local_settings.getFlag3())
        self.checkbox4.setSelected(self.local_settings.getFlag4())
        self.checkbox5.setSelected(self.local_settings.getFlag4())
        self.checkbox6.setSelected(self.local_settings.getFlag4())

    # Return the settings used
    def getSettings(self):
        return self.local_settings

 
