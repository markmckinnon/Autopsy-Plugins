# This python autopsy module will remove custom attributes and artifacts
# to be used by developers as it may fubar your case.
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> gmail [dot] com]
#
# This is free and unencumbered software released only for the use of Autopsy Plugin Developers.
#
# This plugin is not to be used in any production environment or real live cases, only for development work
#
# No one is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, unless permission is 
# granted from the plugin original author (Mark McKinnon).
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Remove custom Artifacts and attributes.
# February 2017
# 
# Comments 
#   Version 1.0 - Initial version - Feb 2017
#   Version 1.1 - Fix options panel GUI - March 2019
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JList
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JFileChooser
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
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
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
class Remove_ArtifactsIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Remove Artifacts/Attributes"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Remove Artifacts and Attributes"
    
    def getModuleVersionNumber(self):
        return "1.2"
    
    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return Remove_ArtifactsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return Remove_ArtifactsIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class Remove_ArtifactsIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(Remove_ArtifactsIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.list_box_entry = []
        self.delete_all_artifacts = False
        self.delete_all_attributes = False

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Check to see if the file to execute exists, if it does not then raise an exception and log error
        # data is taken from the UI

        self.list_box_entry = self.local_settings.getSetting('listSelected')
        self.log(Level.INFO, "List Box Entry Starts here =====>")
        self.log(Level.INFO, str(self.list_box_entry))
        if self.list_box_entry != None:
            for num in range (0, len(self.list_box_entry)):
               self.log(Level.INFO, str(self.list_box_entry[num]))
            self.log(Level.INFO, "<====== List Box Entry Ends here")
        
        if self.local_settings.getSetting('allArtifacts') == 'true':
            self.log(Level.INFO, "Delete All Artifacts")
            self.delete_all_artifacts = True
        else:
            self.log(Level.INFO, "Do Not Delete All Artifacts")
            self.delete_all_artifacts = False
            
        if self.local_settings.getSetting('allAttributes') == 'true':
            self.log(Level.INFO, "Delete All Attributes")
            self.delete_all_attributes = True
        else:
            self.log(Level.INFO, "Do Not Delete All Attributes")
            self.delete_all_attributes = False
        
            
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        if self.delete_all_artifacts:
           sql_statement_1 = "delete from blackboard_attributes where artifact_type_id > 9999;"
           sql_statement_2 = "delete from blackboard_artifacts where artifact_type_id > 9999;"
           sql_statement_3 = "delete from blackboard_artifact_types where artifact_type_id > 9999;"
           sql_statement_4 = "delete from blackboard_attribute_types where attribute_type_id > 9999;"
           case_directory = Temp_Dir = Case.getCurrentCase().getCaseDirectory()
           lclDbPath = os.path.join(case_directory, "autopsy.db")
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) plaso_Import.db3 (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
           try:
               stmt = dbConn.createStatement()
               stmt.execute(sql_statement_1)
               stmt.execute(sql_statement_2)
               stmt.execute(sql_statement_3)
               if self.delete_all_attributes:
                   stmt.execute(sql_statement_4)
           except SQLException as e:
               self.log(Level.INFO, e.getMessage())
           stmt.close()
           dbConn.close()
        elif self.delete_all_attributes:
           sql_statement_1 = "delete from blackboard_attributes where artifact_type_id > 9999;"
           sql_statement_2 = "delete from blackboard_artifacts where artifact_id in (select artifact_id from blackboard_attribute_types where" + \
                             " attribute_type_id > 9999);"
           sql_statement_3 = "delete from blackboard_attribute_types where attribute_type_id > 9999;"
           case_directory = Temp_Dir = Case.getCurrentCase().getCaseDirectory()
           lclDbPath = os.path.join(case_directory, "autopsy.db")
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) plaso_Import.db3 (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
           try:
               stmt = dbConn.createStatement()
               stmt.execute(sql_statement_1)
               stmt.execute(sql_statement_2)
               stmt.execute(sql_statement_3)
           except SQLException as e:
               self.log(Level.INFO, e.getMessage())
           stmt.close()
           dbConn.close()
        else:
            for num in range (0, len(self.list_box_entry)):
               self.log(Level.INFO, str(self.list_box_entry[num]))
               sql_statement_1 = "delete from blackboard_attributes where artifact_type_id in " + \
                                 '(select artifact_type_id from blackboard_artifact_types where type_name = "' + self.list_box_entry[num] + '");'
               sql_statement_2 = "delete from blackboard_artifacts where artifact_type_id in " + \
                                 '(select artifact_type_id from blackboard_artifact_types where type_name = "' + self.list_box_entry[num] + '");'
               case_directory = Temp_Dir = Case.getCurrentCase().getCaseDirectory()
               lclDbPath = os.path.join(case_directory, "autopsy.db")
               try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
               except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) plaso_Import.db3 (" + e.getMessage() + ")")
                   return IngestModule.ProcessResult.OK
               try:
                   stmt = dbConn.createStatement()
                   stmt.execute(sql_statement_1)
                   stmt.execute(sql_statement_2)
               except SQLException as e:
                   self.log(Level.INFO, e.getMessage())
               stmt.close()
               dbConn.close()

               skCase = Case.getCurrentCase().getSleuthkitCase()
               artID_art_evt = skCase.getArtifactType(self.list_box_entry[num])
               IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(Remove_ArtifactsIngestModuleFactory.moduleName, artID_art_evt, None))
                   
           
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Remove_Artifacts", " Remove_Artifacts Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
class Remove_ArtifactsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
        self.artifact_list = []
        self.initComponents()
        #self.customizeComponents()
    
    # Check to see if there are any entries that need to be populated from the database.        
    def checkBoxEvent(self, event):
        if self.All_Artifacts_CB.isSelected():
            self.local_settings.setSetting('allArtifacts', 'true')
            self.List_Box_LB.setEnabled(False)
        else:
            self.local_settings.setSetting('allArtifacts', 'false')
            self.List_Box_LB.setEnabled(True)

        if self.All_Attributes_CB.isSelected():
            self.local_settings.setSetting('allAttributes', 'true')
            self.List_Box_LB.setEnabled(False)
        else:
            self.local_settings.setSetting('allAttributes', 'false')
            self.List_Box_LB.setEnabled(True)

    def onchange_lb(self, event):
        self.local_settings.setSetting('listSelected', '')
        list_selected = self.List_Box_LB.getSelectedValuesList()
        self.local_settings.setSetting('listSelected', list_selected)      

    def get_artifacts(self):
    
        sql_statement = "select distinct(type_name) 'type_name' from blackboard_artifacts a, blackboard_artifact_types b " + \
                        " where a.artifact_type_id = b.artifact_type_id;"
        skCase = Case.getCurrentCase().getSleuthkitCase()
        dbquery = skCase.executeQuery(sql_statement)
        resultSet = dbquery.getResultSet()
        while resultSet.next():
             self.artifact_list.append(resultSet.getString("type_name"))
        dbquery.close()
        
    

    # Create the initial data fields/layout in the UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.All_Artifacts_CB = JCheckBox("Remove All Custom Artifacts", actionPerformed=self.checkBoxEvent)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.All_Artifacts_CB, self.gbcPanel0 ) 
        self.panel0.add( self.All_Artifacts_CB ) 

        self.All_Attributes_CB = JCheckBox("Remove All Custom Attributes", actionPerformed=self.checkBoxEvent)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.All_Attributes_CB, self.gbcPanel0 ) 
        self.panel0.add( self.All_Attributes_CB ) 

        self.Blank_0 = JLabel( " ") 
        self.Blank_0.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_0, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_0 ) 

        self.Label_0 = JLabel( "Remove selected Artifacts") 
        self.Label_0.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_0, self.gbcPanel0 ) 
        self.panel0.add( self.Label_0 ) 

        self.Blank_0 = JLabel( " ") 
        self.Blank_0.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_0, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_0 ) 

        self.get_artifacts()
        self.List_Box_LB = JList( self.artifact_list, valueChanged=self.onchange_lb)
        self.List_Box_LB.setVisibleRowCount( 3 ) 
        self.scpList_Box_LB = JScrollPane( self.List_Box_LB ) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 1 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.scpList_Box_LB, self.gbcPanel0 ) 
        self.panel0.add( self.scpList_Box_LB ) 

        self.Blank_1 = JLabel( " ") 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_1, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_1 ) 

        self.Label_1 = JLabel( "Message:") 
        self.Label_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Label_1 ) 
		
        self.Blank_2 = JLabel( " ") 
        self.Blank_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 13
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_2, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_2 ) 

        self.Error_Message = JLabel( "For developer purposes only, it may fubar your case") 
        self.Error_Message.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 15
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
        self.All_Artifacts_CB.setSelected(self.local_settings.getSetting('allArtifacts') == 'true')
        self.All_Attributes_CB.setSelected(self.local_settings.getSetting('allAttributes') == 'true')

    # Return the settings used
    def getSettings(self):
        return self.local_settings

