# This python autopsy module is an example of the different types of 
# things you can do with the GUI portion of an Autopsy Pythin plugin
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

# GUI_Test module.
# February 2017
# 
# Comments 
#   Version 1.0 - Initial version - Feb 2017
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JComboBox
#from javax.swing import JRadioButton
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
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
class GUI_TestIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "GUI Test"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "GUI Test Example"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return GUI_TestWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GUI_TestWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return GUI_TestWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return GUI_TestIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class GUI_TestIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(GUI_TestIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_GUI_Test = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        
        Combo_Box_entry = self.local_settings.getComboBox()
        self.log(Level.INFO, "Combo Box Entry Starts here =====>")
        self.log(Level.INFO, self.local_settings.getComboBox())
        self.log(Level.INFO, "<====== Combo Box Entry Ends here")
        
        list_box_entry = self.local_settings.getListBox()
        self.log(Level.INFO, "List Box Entry Starts here =====>")
        self.log(Level.INFO, str(list_box_entry))
        for num in range (0, len(list_box_entry)):
           self.log(Level.INFO, str(list_box_entry[num]))
        self.log(Level.INFO, "<====== List Box Entry Ends here")

        # Check to see if the file to import exists, if it does not then raise an exception and log error
        if self.local_settings.getImp_File_Flag():
            self.log(Level.INFO, self.local_settings.getFile_Imp_TF())
            self.path_to_import_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.local_settings.getFile_Imp_TF())
            if not os.path.exists(self.path_to_import_file):
               raise IngestModuleException("File to import is not available")
        
        if self.local_settings.getExec_Prog_Flag():
            self.log(Level.INFO, self.local_settings.getExecFile())
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.local_settings.getExecFile())
            if not os.path.exists(self.path_to_exe):
               raise IngestModuleException("File to Run/execute does not exist.")
        
        
        #self.logger.logp(Level.INFO, GUI_TestWithUI.__name__, "startUp", str(self.List_Of_Events))
        #self.log(Level.INFO, str(self.List_Of_GUI_Test))
		
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process, Just before call to parse_safari_history")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        self.log(Level.INFO, "Starting 2 to process, Just before call to ???????")
        self.log(Level.INFO, "ending process, Just before call to ??????")
        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "GUI_Test", " GUI_Test Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		


# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class GUI_TestWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.Exec_Prog_Flag = False
        self.Imp_File_Flag = False
        self.Check_Box_1 = False
        self.ExecFile = ""
        self.File_Imp_TF = ""
        self.ComboBox = ""
        self.ListBox = []

    def getVersionNumber(self):
        return serialVersionUID

    # Define getters and settings for data you want to store from UI
    def getCheck_Box_1(self):
        return self.Check_Box_1

    def setCheck_Box_1(self, flag):
        self.Check_Box_1 = flag

    def getExec_Prog_Flag(self):
        return self.Exec_Prog_Flag

    def setExec_Prog_Flag(self, flag):
        self.Exec_Prog_Flag = flag

    def getImp_File_Flag(self):
        return self.Imp_File_Flag

    def setImp_File_Flag(self, flag):
        self.Imp_File_Flag = flag

    def getComboBox(self):
        return self.ComboBox

    def setComboBox(self, entry):
        self.ComboBox = entry

    def getListBox(self):
        return self.ListBox

    def clearListBox(self):
        self.ListBox[:] = []

    def setListBox(self, entry):
        self.ListBox = entry

    def getExecFile(self):
        return self.ExecFile

    def setExecFile(self, filename):
        self.ExecFile = filename

    def getFile_Imp_TF(self):
        return self.File_Imp_TF    
        
    def setFile_Imp_TF(self, filename):
        self.File_Imp_TF = filename    
        
# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class GUI_TestWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
        if self.Exec_Program_CB.isSelected():
            self.local_settings.setExec_Prog_Flag(True)
            self.Program_Executable_TF.setEnabled(True)
            self.Find_Program_Exec_BTN.setEnabled(True)
        else:
            self.local_settings.setExec_Prog_Flag(False)
            self.Program_Executable_TF.setText("")
            self.Program_Executable_TF.setEnabled(False)
            self.Find_Program_Exec_BTN.setEnabled(False)

        if self.Imp_File_CB.isSelected():
            self.local_settings.setImp_File_Flag(True)
            self.File_Imp_TF.setEnabled(True)
            self.Find_Imp_File_BTN.setEnabled(True)
        else:
            self.local_settings.setImp_File_Flag(False)
            self.File_Imp_TF.setText("")
            self.local_settings.setFile_Imp_TF("")
            self.File_Imp_TF.setEnabled(False)
            self.Find_Imp_File_BTN.setEnabled(False)

    def keyPressed(self, event):
        self.local_settings.setArea(self.area.getText()) 

    def onchange_cb(self, event):
        self.local_settings.setComboBox(event.item) 
        #self.Error_Message.setText(event.item)

    def onchange_lb(self, event):
        self.local_settings.clearListBox()
        list_selected = self.List_Box_LB.getSelectedValuesList()
        self.local_settings.setListBox(list_selected)      
        # if (len(list_selected) > 0):
            # self.Error_Message.setText(str(list_selected))
        # else:
            # self.Error_Message.setText("")

    def onClick(self, e):

       chooseFile = JFileChooser()
       filter = FileNameExtensionFilter("SQLite", ["sqlite"])
       chooseFile.addChoosableFileFilter(filter)

       ret = chooseFile.showDialog(self.panel0, "Select SQLite")

       if ret == JFileChooser.APPROVE_OPTION:
           file = chooseFile.getSelectedFile()
           Canonical_file = file.getCanonicalPath()
           #text = self.readPath(file)
           if self.File_Imp_TF.isEnabled():
              self.File_Imp_TF.setText(Canonical_file)
              self.local_settings.setFile_Imp_TF(Canonical_file)
           else:
              self.local_settings.setExecFile(Canonical_file)
              self.Program_Executable_TF.setText(Canonical_file)

    # TODO: Update this for your UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Exec_Program_CB = JCheckBox("Execute Program", actionPerformed=self.checkBoxEvent)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Exec_Program_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Exec_Program_CB ) 

        self.Program_Executable_TF = JTextField(20) 
        self.Program_Executable_TF.setEnabled(False)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Program_Executable_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Program_Executable_TF ) 

        self.Find_Program_Exec_BTN = JButton( "Find Exec", actionPerformed=self.onClick)
        self.Find_Program_Exec_BTN.setEnabled(False)
        self.rbgPanel0.add( self.Find_Program_Exec_BTN ) 
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Find_Program_Exec_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Find_Program_Exec_BTN ) 

        self.Imp_File_CB = JCheckBox( "Import File", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Imp_File_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Imp_File_CB ) 

        self.File_Imp_TF = JTextField(20) 
        self.File_Imp_TF.setEnabled(False)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.File_Imp_TF, self.gbcPanel0 ) 
        self.panel0.add( self.File_Imp_TF ) 

        self.Find_Imp_File_BTN = JButton( "Find File", actionPerformed=self.onClick) 
        self.Find_Imp_File_BTN.setEnabled(False)
        self.rbgPanel0.add( self.Find_Imp_File_BTN ) 
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Find_Imp_File_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Find_Imp_File_BTN ) 

        self.Check_Box_CB = JCheckBox( "Check Box 1", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Check_Box_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Check_Box_CB ) 

        self.dataComboBox_CB = ("Chocolate", "Ice Cream", "Apple Pie") 
        self.ComboBox_CB = JComboBox( self.dataComboBox_CB)
        self.ComboBox_CB.itemStateChanged = self.onchange_cb        
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.ComboBox_CB, self.gbcPanel0 ) 
        self.panel0.add( self.ComboBox_CB ) 
        
        self.dataList_Box_LB = ("Chocolate", "Ice Cream", "Apple Pie", "Pudding", "Candy" )
        self.List_Box_LB = JList( self.dataList_Box_LB, valueChanged=self.onchange_lb)
        #self.List_Box_LB.itemStateChanged = self.onchange_lb
        self.List_Box_LB.setVisibleRowCount( 3 ) 
        self.scpList_Box_LB = JScrollPane( self.List_Box_LB ) 
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 15 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 1 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.scpList_Box_LB, self.gbcPanel0 ) 
        self.panel0.add( self.scpList_Box_LB ) 

        # self.Radio_Button_RB = JRadioButton( "Radio Button"  ) 
        # self.rbgPanel0.add( self.Radio_Button_RB ) 
        # self.gbcPanel0.gridx = 7 
        # self.gbcPanel0.gridy = 17
        # self.gbcPanel0.gridwidth = 1 
        # self.gbcPanel0.gridheight = 1 
        # self.gbcPanel0.fill = GridBagConstraints.BOTH 
        # self.gbcPanel0.weightx = 1 
        # self.gbcPanel0.weighty = 0 
        # self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        # self.gbPanel0.setConstraints( self.Radio_Button_RB, self.gbcPanel0 ) 
        # self.panel0.add( self.Radio_Button_RB ) 

        # self.Label_1 = JLabel( "Error Message:") 
        # self.Label_1.setEnabled(True)
        # self.gbcPanel0.gridx = 2 
        # self.gbcPanel0.gridy = 19
        # self.gbcPanel0.gridwidth = 1 
        # self.gbcPanel0.gridheight = 1 
        # self.gbcPanel0.fill = GridBagConstraints.BOTH 
        # self.gbcPanel0.weightx = 1 
        # self.gbcPanel0.weighty = 0 
        # self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        # self.gbPanel0.setConstraints( self.Label_1, self.gbcPanel0 ) 
        # self.panel0.add( self.Label_1 ) 
		
        # self.Error_Message = JLabel( "") 
        # self.Error_Message.setEnabled(True)
        # self.gbcPanel0.gridx = 6
        # self.gbcPanel0.gridy = 19
        # self.gbcPanel0.gridwidth = 1 
        # self.gbcPanel0.gridheight = 1 
        # self.gbcPanel0.fill = GridBagConstraints.BOTH 
        # self.gbcPanel0.weightx = 1 
        # self.gbcPanel0.weighty = 0 
        # self.gbcPanel0.anchor = GridBagConstraints.NORTH
        # self.gbPanel0.setConstraints( self.Error_Message, self.gbcPanel0 ) 
        # self.panel0.add( self.Error_Message ) 
		
        self.add(self.panel0)

    # TODO: Update this for your UI
    def customizeComponents(self):
        self.Exec_Program_CB.setSelected(self.local_settings.getExec_Prog_Flag())
        self.Imp_File_CB.setSelected(self.local_settings.getImp_File_Flag())
        self.Check_Box_CB.setSelected(self.local_settings.getCheck_Box_1())

    # Return the settings used
    def getSettings(self):
        return self.local_settings

