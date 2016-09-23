# This python autopsy module will parse any SQLite databases and look for deleted records
# it will create a SQLite database with the deleted records and then import the information into  
# the extracted content.  The executable program is a modified version of the python script 
# from Mari Degrazia's SQLite Deleted Records Parser.
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

# Parse Sqlite Del Records module to parse the SQLite databases from.
# Sept 2016
# 
# Comments 
#   Version 1.0 - Initial version - Sept 2016 
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE

from javax.swing import JCheckBox
from javax.swing import JLabel
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
from java.awt.event import KeyEvent
from java.awt.event import KeyAdapter
from javax.swing.event import DocumentEvent
from javax.swing.event import DocumentListener

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
class ParseSQLiteDBDelRecIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Parse SQLite Del Rec"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parse SQLite Deleted Records"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return GUI_PSQLiteUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GUI_PSQLiteUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return GUI_PSQLiteUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseSQLiteDBDelRecIngestModule(self.settings)


# Data Source-level ingest module.  One gets created per data source.
class ParseSQLiteDBDelRecIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseSQLiteDBDelRecIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_DBs = []
       
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        if self.local_settings.getFlag():
            #self.List_Of_DBs.append('Other')
            DBs_List = self.local_settings.getArea().split(',')
            for DBs in DBs_List:
                self.List_Of_DBs.append(str(DBs).strip('\n').replace(' ',''))
        
        #self.logger.logp(Level.INFO, GUI_TestWithUI.__name__, "startUp", str(self.List_Of_Events))
        self.log(Level.INFO, str(self.List_Of_DBs))
   
        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sqlparse_v2_autopsy.exe")
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

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        for SQLite_DB in self.List_Of_DBs:
            files = fileManager.findFiles(dataSource, SQLite_DB)
            numFiles = len(files)
            self.log(Level.INFO, "found " + str(numFiles) + " files")
            progressBar.switchToDeterminate(numFiles)
            fileCount = 0;
                    
            for file in files:	
               # Open the DB using JDBC
               #lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), SQLite_DB)
               lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), file.getName() + "-" + str(file.getId()))
               ContentUtils.writeToFile(file, File(lclDbPath))

               # Run the EXE, saving output to a sqlite database
               self.log(Level.INFO, "Running program ==> " + self.path_to_exe + " " + Temp_Dir + "\\" + \
                        file.getName() + "-" + str(file.getId()) + " " + Temp_Dir + "\\SQLite_Del_Records-" + str(file.getId()) + ".db3 ")
               pipe = Popen([self.path_to_exe, Temp_Dir + "\\" + file.getName() + "-" + str(file.getId()), Temp_Dir + \
                         "\\SQLite_Del_Records-" + str(file.getId()) + ".db3"], stdout=PIPE, stderr=PIPE)
               out_text = pipe.communicate()[0]
               self.log(Level.INFO, "Output from run is ==> " + out_text)               
           
               extDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "SQLite_Del_Records-" + str(file.getId()) + ".db3")

               #self.log(Level.INFO, "Path the sqlite database file created ==> " + lclDbPath)
               try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % extDbPath)
                   self.log(Level.INFO, "Database ==> " + file.getName())
               except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + extDbPath + " (" + e.getMessage() + ")")
                   #return IngestModule.ProcessResult.OK
                
               # Query the contacts table in the database and get all columns. 
               try:
                   stmt = dbConn.createStatement()
                   stmt2 = dbConn.createStatement()
                   stmt3 = dbConn.createStatement()
                   stmt4 = dbConn.createStatement()
                   resultSet = stmt.executeQuery("Select tbl_name, type from SQLITE_MASTER where type in ('table','view');")
                   #self.log(Level.INFO, "query SQLite Master table")
                   #self.log(Level.INFO, "query " + str(resultSet))

                   # Cycle through each row and create artifacts
                   while resultSet.next():
                       try: 
                          self.log(Level.INFO, "Result (" + resultSet.getString("tbl_name") + ")")
                          table_name = resultSet.getString("tbl_name")
                          object_type = resultSet.getString("type")
                          resultSet4  = stmt4.executeQuery("Select count(*) 'NumRows' from " + resultSet.getString("tbl_name") + " ")
 #                          while resultSet4.next():
                          row_count = resultSet4.getInt("NumRows")
                          self.log(Level.INFO, " Number of Rows is " + str(row_count) + " ")                           
                          if row_count >= 1:
                               #self.log(Level.INFO, "Result get information from table " + resultSet.getString("tbl_name") + " ")
                               SQL_String_1 = "Select * from " + table_name + ";"
                               SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
                               #self.log(Level.INFO, SQL_String_1)
                               #self.log(Level.INFO, SQL_String_2)
                               artifact_name = "TSK_" + SQLite_DB.upper() + "_" + table_name.upper()
                               artifact_desc = "SQLite Database  " + SQLite_DB.upper() + "  " + object_type.title()  + "  "+ table_name.upper()
                               #self.log(Level.INFO, "Artifact Name ==> " + artifact_name + "  Artifact Desc ==> " + artifact_desc)
                               try:
                                    #self.log(Level.INFO, "Begin Create New Artifacts")
                                    artID_sql = skCase.addArtifactType( artifact_name, artifact_desc)
                               except:		
                                    self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

                               artID_sql = skCase.getArtifactTypeID(artifact_name)
                               artID_sql_evt = skCase.getArtifactType(artifact_name)
                                                      
                               Column_Names = []
                               Column_Types = []
                               resultSet2  = stmt2.executeQuery(SQL_String_2)
                               while resultSet2.next(): 
                                  Column_Names.append(resultSet2.getString("name").upper())
                                  Column_Types.append(resultSet2.getString("type").upper())
                                  #self.log(Level.INFO, "Add Attribute TSK_" + resultSet2.getString("name").upper() + " ==> " + resultSet2.getString("name"))
                                  ##attID_ex1 = skCase.addAttrType("TSK_" + resultSet2.getString("name").upper(), resultSet2.getString("name"))
                                  ##self.log(Level.INFO, "attribure id for " + "TSK_" + resultSet2.getString("name") + " == " + str(attID_ex1))
                                  attribute_name = "TSK_" + SQLite_DB + "_" + table_name.upper() + "_" + resultSet2.getString("name").upper()
                                  #self.log(Level.INFO, "attribure id for " + attribute_name + " == " + resultSet2.getString("type").upper())
                                  if resultSet2.getString("type").upper() == "TEXT":
                                      try:
                                          attID_ex1 = skCase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                                      except:		
                                          self.log(Level.INFO, "Attributes Creation Error, " + attribute_name + " ==> ")
                                  elif resultSet2.getString("type").upper() == "LONGVARCHAR":
                                      try:
                                          attID_ex1 = skCase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                                      except:		
                                          self.log(Level.INFO, "Attributes Creation Error, " + attribute_name + " ==> ")
                                  elif resultSet2.getString("type").upper() == "":
                                      try:
                                          attID_ex1 = skCase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                                      except:		
                                          self.log(Level.INFO, "Attributes Creation Error, " + attribute_name + " ==> ")
                                  elif resultSet2.getString("type").upper() == "BLOB":
                                      try:
                                          attID_ex1 = skCase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                                      except:		
                                          self.log(Level.INFO, "Attributes Creation Error, " + attribute_name + " ==> ")
                                  elif resultSet2.getString("type").upper() == "REAL":
                                      try:
                                          attID_ex1 = skCase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet2.getString("name"))
                                      except:		
                                          self.log(Level.INFO, "Attributes Creation Error, " + attribute_name + " ==> ")
                                  else:
                                      try:
                                          attID_ex1 = skCase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet2.getString("name"))
                                      except:		
                                          self.log(Level.INFO, "Attributes Creation Error, " + attribute_name + " ==> ")

                                                     
                               resultSet3 = stmt3.executeQuery(SQL_String_1)
                               while resultSet3.next():
                                  art = file.newArtifact(artID_sql)
                                  Column_Number = 1
                                  for col_name in Column_Names:
                                     #self.log(Level.INFO, "Result get information for column " + Column_Names[Column_Number - 1] + " ")
                                     #self.log(Level.INFO, "Result get information for column_number " + str(Column_Number) + " ")
                                     #self.log(Level.INFO, "Result get information for column type " + Column_Types[Column_Number - 1] + " <== ")
                                     c_name = "TSK_" + SQLite_DB + "_" + table_name.upper() + "_" + Column_Names[Column_Number - 1]
                                     #self.log(Level.INFO, "Attribute Name is " + c_name + " ")
                                     attID_ex1 = skCase.getAttributeType(c_name)
                                     if Column_Types[Column_Number - 1] == "TEXT":
                                         art.addAttribute(BlackboardAttribute(attID_ex1, ParseSQLiteDBDelRecIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                                     elif Column_Types[Column_Number - 1] == "":
                                         art.addAttribute(BlackboardAttribute(attID_ex1, ParseSQLiteDBDelRecIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                                     elif Column_Types[Column_Number - 1] == "LONGVARCHAR":
                                         art.addAttribute(BlackboardAttribute(attID_ex1, ParseSQLiteDBDelRecIngestModuleFactory.moduleName, "BLOBS Not Supported - Look at actual file"))
                                     elif Column_Types[Column_Number - 1] == "BLOB":
                                         art.addAttribute(BlackboardAttribute(attID_ex1, ParseSQLiteDBDelRecIngestModuleFactory.moduleName, "BLOBS Not Supported - Look at actual file"))
                                     elif Column_Types[Column_Number - 1] == "REAL":
                                         art.addAttribute(BlackboardAttribute(attID_ex1, ParseSQLiteDBDelRecIngestModuleFactory.moduleName, long(resultSet3.getFloat(Column_Number))))
                                     else:
                                         art.addAttribute(BlackboardAttribute(attID_ex1, ParseSQLiteDBDelRecIngestModuleFactory.moduleName, long(resultSet3.getInt(Column_Number))))
                                     Column_Number = Column_Number + 1
                               
                               IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseSQLiteDBDelRecIngestModuleFactory.moduleName, \
                                    artID_sql_evt, None))
                                
                       except SQLException as e:
                           self.log(Level.INFO, "Error getting values from table " +  resultSet.getString("tbl_name") + " (" + e.getMessage() + ")")
               except SQLException as e:
                   self.log(Level.INFO, "Error querying database " + file.getName() + " (" + e.getMessage() + ")")
                   #return IngestModule.ProcessResult.OK
               # Clean up
               stmt.close()
               dbConn.close()
               os.remove(Temp_Dir + "\\" + file.getName() + "-" + str(file.getId()))
               os.remove(Temp_Dir + "\\SQLite_Del_Records-" + str(file.getId()) + ".db3")
               
                
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "SQLite Database Parser", " SQLite Databases have been parsed  " )
        IngestServices.getInstance().postMessage(message)

        
        return IngestModule.ProcessResult.OK

class GUI_PSQLiteUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.flag = False
        self.area = ""

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def getFlag(self):
        return self.flag

    def setFlag(self, flag):
        self.flag = flag

    def getArea(self):
        return self.area

    def setArea(self, area):
        self.area = area
        
class GUI_PSQLiteUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
            self.local_settings.setArea(self.area.getText());
        else:
            self.local_settings.setFlag(False)

    # TODO: Update this for your UI
    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        #self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.panel1 = JPanel()
        self.panel1.setLayout(BoxLayout(self.panel1, BoxLayout.Y_AXIS))
        self.panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.checkbox = JCheckBox("Check to activate/deactivate TextArea", actionPerformed=self.checkBoxEvent)
        self.label0 = JLabel(" ")
        self.label1 = JLabel("Input in SQLite DB's in area below,")
        self.label2 = JLabel("seperate values by commas.")
        self.label3 = JLabel("then check the box above.")
        self.label4 = JLabel(" ")
        self.panel1.add(self.checkbox)
        self.panel1.add(self.label0)
        self.panel1.add(self.label1)
        self.panel1.add(self.label2)
        self.panel1.add(self.label3)
        self.panel1.add(self.label4)
        self.add(self.panel1)
 
        self.area = JTextArea(5,25)
        #self.area.getDocument().addDocumentListener(self.area)
        #self.area.addKeyListener(listener)
        self.area.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))
        self.pane = JScrollPane()
        self.pane.getViewport().add(self.area)
        #self.pane.addKeyListener(self.area)
        #self.add(self.area)
        self.add(self.pane)
		


    # TODO: Update this for your UI
    def customizeComponents(self):
        self.checkbox.setSelected(self.local_settings.getFlag())

    # Return the settings used
    def getSettings(self):
        return self.local_settings

