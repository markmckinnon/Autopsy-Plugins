# This python autopsy module will Export time related data to a json_line file
# and then call an external program to upload the json_line file to timesketch
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

# Timesketch.
# October 2018
# 
# Comments 
#   Version 1.0 - Initial version - October 2018
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE
import json

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JList
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import JComboBox
from javax.swing import JPasswordField
from javax.swing.filechooser import FileNameExtensionFilter

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
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class TimesketchIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Timesketch Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Send Date Artifacts to Timesketch"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return TimesketchSettingsWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, TimesketchSettingsWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return TimesketchSettingsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return TimesketchIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class TimesketchIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(TimesketchIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.userName = self.local_settings.getuserName()
        self.password = self.local_settings.getpassword()
        self.IP_Address = self.local_settings.getIP_Address()
        self.Port_Number = self.local_settings.getPort_Number()
        self.sketchName = self.local_settings.getsketchName()
        self.sketchDescription = self.local_settings.getsketchDescription()

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        #Show parameters that are passed in
        self.log(Level.INFO, "Username  =====>" + str(self.userName))
        self.log(Level.INFO, "password  =====>" + str(self.password))
        self.log(Level.INFO, "IP Address  =====>" + str(self.IP_Address))
        self.log(Level.INFO, "Port_Number  =====>" + str(self.Port_Number))
        self.log(Level.INFO, "Sketch Name =====> " + str(self.sketchName))
        self.log(Level.INFO, "sketch Description =====> " + str(self.sketchDescription))
        
        # Check to see if the file to execute exists, if it does not then raise an exception and log error
        # data is taken from the UI
        self.path_to_Timesketch_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "timesketch_autopsy.exe")
        if not os.path.exists(self.path_to_Timesketch_exe):
            raise IngestModuleException("Timesketch_autopsy.exe was not found in module folder")
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process, Just before call to parse_safari_history")

        # Setup SQL Statements and other variables
        artifactSQL = 'select distinct "artifact_type_name:" a1, art_type.type_name a2, "artifact_display_name:" b1, art_type.display_name b2, ' + \
              ' "datasource_obj_id:" c1, img_name.obj_id c2, "datasource_name:" d1, img_name.name d2, art_type.type_name e1 from blackboard_artifact_types art_type, ' + \
              ' tsk_image_names img_name, blackboard_artifacts art, blackboard_attributes att where img_name.obj_id = art.data_source_obj_id ' + \
              ' and img_name.sequence = 0 and art.artifact_type_id = art_type.artifact_type_id and att.artifact_id = art.artifact_id ' + \
              ' and att.artifact_id = '
        artifactSQL2 = 'select att_type.display_name date_type, case att.value_type when 0 then value_text when 1 then value_int32 when 2 then value_int64 ' +\
               ' when 3 then value_double when 4 then value_byte when 5 then value_int64 end date_value from blackboard_attributes att, ' + \
               ' blackboard_attribute_types att_type where att_type.attribute_type_id = att.attribute_type_id and att.value_type = 5 ' + \
               ' and att.artifact_id = '
        artifactSQL3 = 'select att_type.display_name name, case att.value_type when 0 then value_text when 1 then value_int32 when 2 then value_int64 ' +\
               ' when 3 then value_double when 4 then value_byte when 5 then value_int64 end value from blackboard_attributes att, ' + \
               ' blackboard_attribute_types att_type where att_type.attribute_type_id = att.attribute_type_id and att.value_type <> 5 ' + \
               ' and att.artifact_id = '
        sketchName = self.sketchName
        sketchDescription = self.sketchDescription
        timelineName = sketchName + "_Timeline"
        timelineIndex = sketchName + "_Index"
        jsonFileName = "Autopsy.jsonl"
        skCase = Case.getCurrentCase().getSleuthkitCase()

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
		# Create Event Log directory in temp directory, if it exists then continue on processing		
        tempDirectory = Case.getCurrentCase().getTempDirectory()
        tempDir = os.path.join(tempDirectory, "Timesketch")

        self.log(Level.INFO, "create Directory " + tempDir)
        try:
            os.mkdir(tempDir)
        except:
            self.log(Level.INFO, "Timesketch directory already exists" + tempDir)
            
        artList = []
        dbquery = skCase.executeQuery("select distinct artifact_id from blackboard_attributes where value_type = 5;")
        resultSet = dbquery.getResultSet()
        while resultSet.next():
            artifactDict = {}
            dbquery2 = skCase.executeQuery(artifactSQL + resultSet.getString("artifact_id"))
            resultSet2 = dbquery2.getResultSet()
            while resultSet2.next():
                artifactDict[resultSet2.getString("a1")] = resultSet2.getString("a2")
                artifactDict[resultSet2.getString("b1")] = resultSet2.getString("b2")
                artifactDict[resultSet2.getString("c1")] = resultSet2.getString("c2")
                artifactDict[resultSet2.getString("d1")] = resultSet2.getString("d2")
                dbquery3 = skCase.executeQuery(artifactSQL2 + resultSet.getString("artifact_id"))
                resultSet3 = dbquery3.getResultSet()
                while resultSet3.next():
                   artifactDict[resultSet3.getString("date_type")] = resultSet3.getString("date_value")   
                   artifactDict["message"] = resultSet2.getString("e1")
                   artifactDict["timestamp_desc"] = resultSet3.getString("date_type")
                   artifactDict["timestamp"] = resultSet3.getString("date_value")
                   dbquery4 = skCase.executeQuery(artifactSQL3 + resultSet.getString("artifact_id"))
                   resultSet4 = dbquery4.getResultSet()
                   while resultSet4.next():
                       artValue = resultSet4.getString("value")
                       artName = resultSet4.getString("name")
                       if isinstance(artValue, unicode):
                          #print (artValue)
                          artifactDict[artName] = artValue.translate({0x2014: None})
                       else:
                          artifactDict[artName] = artValue
                   dbquery4.close()
                dbquery3.close()
            dbquery2.close()     

            artList.append(artifactDict)
        dbquery.close()

        # Get file Times
        fileList = []
        dbquery = skCase.executeQuery("Select obj_id from tsk_files")
        resultSet = dbquery.getResultSet()
        while resultSet.next():
            dbquery2 = skCase.executeQuery("Select ctime, crtime, atime, mtime, parent_path||name from tsk_files where obj_id = " + \
                                           resultSet.getString("obj_id"))
            resultSet2 = dbquery2.getResultSet()
            meta = resultSet2.getMetaData()
            columnCount = meta.getColumnCount()
            column_names = []  # ?? Do I need this
            while resultSet2.next():
                for i in range (1,int(columnCount)):
                    fileDict = {}
                    if resultSet2.getString(i) is None:
                        fileDict[meta.getColumnLabel(i)] = ""
                        fileDict["message"] = "TSK : "
                        fileDict["timestamp"] = 0
                    else:
                        fileDict[meta.getColumnLabel(i)] = resultSet2.getString(i)
                        fileDict["message"] = "TSK : " + resultSet2.getString(5)
                        fileDict["timestamp"] = resultSet2.getString(i)
                    fileDict["timestamp_desc"] = meta.getColumnLabel(i)
                    dbquery3 = skCase.executeQuery("Select * from tsk_files where obj_id = " + resultSet.getString("obj_id"))
                    resultSet3 = dbquery3.getResultSet()
                    meta3 = resultSet3.getMetaData()
                    columnCount3 = meta3.getColumnCount()
                    while resultSet3.next():
                        for x in range(1,int(columnCount3)):
                            colHead = meta3.getColumnLabel(x)
                            if (('ctime' in colHead) or ('crtime' in colHead) or ('atime' in colHead) or ('mtime' in  colHead)):
                                #self.log(Level.INFO, "Heading ==> " + colHead )
                                pass
                            else:
                                if resultSet3.getString(x) is  None:
                                    fileDict[colHead] = ""
                                else:
                                    fileDict[colHead] = resultSet3.getString(x)
                    dbquery3.close()
                    fileList.append(fileDict)

            dbquery2.close()        
        dbquery.close()
        
        jsonFileNamePath = os.path.join(tempDir, jsonFileName)
        
        with open(jsonFileNamePath, 'w') as f:
            for art in artList:
                json.dump(art, f)
                f.write("\n")
            for file in fileList:
                json.dump(file, f)
                f.write("\n")

        # Check Messages
        # TS001 - Invalid arguments
        # TS002 - Sketch Created
        # TS003 - Sketch Already Exists
        # TS004 - Error Looking up Sketch
        # TS005 - Timeline Added
        # TS006 - Timeline Not Created
        # Try to run this 3 times in case you add a sketch but for some reason you fail to add a the timeline,
        # you may be able to add the timeline on another run, no reason to make the user run this multple times
        # when we can do that as well.

        emessage = "Internal Error contact plugin maker"
        for z in range(3):
            self.log(Level.INFO, "command ==> " + self.path_to_Timesketch_exe + " " + sketchName + " " + jsonFileNamePath + " " + self.IP_Address + " " + self.Port_Number + " " + self.userName + " " + self.password)
            pipe = Popen([self.path_to_Timesketch_exe, sketchName, jsonFileNamePath, self.IP_Address, self.Port_Number, self.userName, self.password], stdout=PIPE, stderr=PIPE)
            out_text = pipe.communicate()[0]
            self.log(Level.INFO, "Output from run is ==> " + out_text)
            if "TS005" in out_text:
                if "TS002" in out_text:
                    emessage = "Sketch added, Timeline added"
                    break
                elif "TS003" in out_text:
                    emessage = "Sketch already exists, Timeline added"
                    break
            elif "TS001" in out_text:
                emessage = "invalid parameters passed in, missing parameters"
                break
            elif "TS006" in out_text:
                if "TSK004" in out_text:
                    emessage = "Error Looking up sketch, Timeline Not Created"
            

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Timesketch File Submit",  emessage )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
class TimesketchSettingsWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.Port_Number = ""
        self.IP_Address = ""
        self.userName = ""
        self.password = ""
        self.sketchName = ""
        self.sketchDescription = ""

        
    def getVersionNumber(self):
        return serialVersionUID

    # Define getters and settings for data you want to store from UI
    def getProtocol(self):
        return self.Protocol

    def setProtocol(self, flag):
        self.Protocol = flag
        
    def getPort_Number(self):
        return self.Port_Number

    def setPort_Number(self, flag):
        self.Port_Number = flag
        
    def getIP_Address(self):
        return self.IP_Address

    def setIP_Address(self, flag):
        self.IP_Address = flag
        
    def getuserName(self):
        return self.userName

    def setuserName(self, flag):
        self.userName = flag
        
    def getpassword(self):
        return self.password

    def setpassword(self, flag):
        self.password = flag
        
    def getsketchName(self):
        return self.sketchName

    def setsketchName(self, flag):
        self.sketchName = flag
        
    def getsketchDescription(self):
        return self.sketchDescription

    def setsketchDescription(self, flag):
        self.sketchDescription = flag
        
    
# UI that is shown to user for each ingest job so they can configure the job.
class TimesketchSettingsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
    def __init__(self, settings):
        self.local_settings = settings
        self.tag_list = []
        self.initComponents()
        self.customizeComponents()
        self.path_to_Timesketch_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Timesketch_api.exe")
 

    # Check to see if there are any entries that need to be populated from the database.        
    def check_Database_entries(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\gui_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings DB!")
 
        try:
           stmt = dbConn.createStatement()
           SQL_Statement = 'Select Timesketch_host, Timesketch_port from Timesketch_server' 
           resultSet = stmt.executeQuery(SQL_Statement)
           while resultSet.next():
               self.IP_Address_TF.setText(resultSet.getString("Timesketch_host"))
               self.Port_Number_TF.setText(resultSet.getString("Timesketch_port"))
               self.local_settings.setIP_Address(resultSet.getString("Timesketch_host"))
               self.local_settings.setPort_Number(resultSet.getString("Timesketch_port"))
           self.Error_Message.setText("Settings Read successfully!")
        except SQLException as e:
            self.Error_Message.setText("Error Reading Settings Database")

        stmt.close()
        dbConn.close()

    # Save entries from the GUI to the database.
    def SaveSettings(self, e):
        
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\GUI_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings")
 
        try:
           stmt = dbConn.createStatement()
           SQL_Statement = ""
           SQL_Statement = 'Update Timesketch_server set Timesketch_Host = "' + self.IP_Address_TF.getText() + '", ' + \
                               '                     Timesketch_port = "' + self.Port_Number_TF.getText() + '";' 
           
           #self.Error_Message.setText(SQL_Statement)
           stmt.execute(SQL_Statement)
           self.Error_Message.setText("Timesketch settings Saved")
           #self.local_settings.setTimesketch_Directory(self.Program_Executable_TF.getText())
        except SQLException as e:
           self.Error_Message.setText(e.getMessage())
        stmt.close()
        dbConn.close()
           
    # Check to see if the Timesketch server is available and you can talk to it
    def Check_Server(self, e):

       pipe = Popen([self.path_to_Timesketch_exe, self.Protocol_TF.getText(),self.IP_Address_TF.getText(), self.Port_Number_TF.getText(), "Timesketch_status" ], stdout=PIPE, stderr=PIPE)
        
       out_text = pipe.communicate()[0]
       self.Error_Message.setText("Timesketch Status is " + out_text)
       #self.log(Level.INFO, "Timesketch Status is ==> " + out_text)

           
    def setUserName(self, event):
        self.local_settings.setuserName(self.userName_TF.getText()) 

    def setPassword(self, event):
        self.local_settings.setpassword(self.password_TF.getText()) 

    def setsketchName(self, event):
        self.local_settings.setsketchName(self.sketchName_TF.getText()) 

    def setsketchDescription(self, event):
        self.local_settings.setsketchDescription(self.sketchDescription_TF.getText()) 

    # Create the initial data fields/layout in the UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Label_2 = JLabel("Timesketch IP Address")
        self.Label_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_2, self.gbcPanel0 ) 
        self.panel0.add( self.Label_2 ) 

        self.IP_Address_TF = JTextField(20) 
        self.IP_Address_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.IP_Address_TF, self.gbcPanel0 ) 
        self.panel0.add( self.IP_Address_TF ) 

        self.Blank_2 = JLabel( " ") 
        self.Blank_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_2, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_2 ) 

        self.Label_3 = JLabel("Port Number")
        self.Label_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_3, self.gbcPanel0 ) 
        self.panel0.add( self.Label_3 ) 

        self.Port_Number_TF = JTextField(20) 
        self.Port_Number_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Port_Number_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Port_Number_TF ) 

        self.Blank_3 = JLabel( " ") 
        self.Blank_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_3, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_3 ) 
        
        self.Save_Settings_BTN = JButton( "Save Setup", actionPerformed=self.SaveSettings) 
        self.Save_Settings_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Save_Settings_BTN ) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 13
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Save_Settings_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Save_Settings_BTN ) 

        self.Blank_X = JLabel( " ") 
        self.Blank_X.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_X, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_X ) 

        self.Label_4 = JLabel("User Name")
        self.Label_4.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 17 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_4, self.gbcPanel0 ) 
        self.panel0.add( self.Label_4 ) 

        self.userName_TF = JTextField(20, focusLost=self.setUserName) 
        self.userName_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 17 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.userName_TF, self.gbcPanel0 ) 
        self.panel0.add( self.userName_TF ) 

        self.Blank_4 = JLabel( " ") 
        self.Blank_4.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 19
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_4, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_4 ) 

        self.Label_5 = JLabel("Password")
        self.Label_5.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 21 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_5, self.gbcPanel0 ) 
        self.panel0.add( self.Label_5 ) 

        self.password_TF = JPasswordField(20, focusLost=self.setPassword) 
#        self.password_TF = JTextField(20) 
        self.password_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 21 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.password_TF, self.gbcPanel0 ) 
        self.panel0.add( self.password_TF ) 

        self.Blank_5 = JLabel( " ") 
        self.Blank_5.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 23
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_5, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_5 ) 
        
        self.Label_6 = JLabel("Sketch Name")
        self.Label_6.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 25 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_6, self.gbcPanel0 ) 
        self.panel0.add( self.Label_6 ) 

        self.sketchName_TF = JTextField(20, focusLost=self.setsketchName) 
        self.sketchName_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 25 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.sketchName_TF, self.gbcPanel0 ) 
        self.panel0.add( self.sketchName_TF ) 

        self.Blank_6 = JLabel( " ") 
        self.Blank_6.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 27
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_6, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_6 ) 

        self.Label_7 = JLabel("Sketch Description")
        self.Label_7.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 29 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_7, self.gbcPanel0 ) 
        self.panel0.add( self.Label_7 ) 

        self.sketchDescription_TF = JTextField(20, focusLost=self.setsketchDescription) 
        self.sketchDescription_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 29 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.sketchDescription_TF, self.gbcPanel0 ) 
        self.panel0.add( self.sketchDescription_TF ) 

        self.Blank_7 = JLabel( " ") 
        self.Blank_7.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 31
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_7, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_7 ) 
        
        # self.Check_Server_Status_BTN = JButton( "Check Server Status", actionPerformed=self.Check_Server) 
        # self.Check_Server_Status_BTN.setEnabled(True)
        # self.rbgPanel0.add( self.Save_Settings_BTN ) 
        # self.gbcPanel0.gridx = 2 
        # self.gbcPanel0.gridy = 33
        # self.gbcPanel0.gridwidth = 1 
        # self.gbcPanel0.gridheight = 1 
        # self.gbcPanel0.fill = GridBagConstraints.BOTH 
        # self.gbcPanel0.weightx = 1 
        # self.gbcPanel0.weighty = 0 
        # self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        # self.gbPanel0.setConstraints( self.Check_Server_Status_BTN, self.gbcPanel0 ) 
        # self.panel0.add( self.Check_Server_Status_BTN ) 

        self.Error_Message = JLabel( "") 
        self.Error_Message.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 35
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints( self.Error_Message, self.gbcPanel0 ) 
        self.panel0.add( self.Error_Message ) 


        self.add(self.panel0)

    # Custom load any data field and initialize the values
    def customizeComponents(self):
        #self.Exclude_File_Sources_CB.setSelected(self.local_settings.getExclude_File_Sources())
        #self.Run_Timesketch_CB.setSelected(self.local_settings.getRun_Timesketch())
        #self.Import_Timesketch_CB.setSelected(self.local_settings.getImport_Timesketch())
        self.check_Database_entries()
        self.sketchName_TF.setText(Case.getCurrentCase().getNumber())
        self.sketchDescription_TF.setText(Case.getCurrentCase().getName())
        self.local_settings.setsketchName(self.sketchName_TF.getText()) 
        self.local_settings.setsketchDescription(self.sketchDescription_TF.getText()) 


    # Return the settings used
    def getSettings(self):
        return self.local_settings
