# This python autopsy module will convert crashdumps and hiberfiles using 
# Volatility against a disk image.  
# It will ask the user for the directory where the Volatility executables reside 
# then it will run volatility against the Disk image using options the 
# user specifies.
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

# Volatility_Convert.
# August 2017
# 
# Comments 
#   Version 1.0 - Initial version - August 2017
# 

import jarray
import inspect
import os
#import distutils
from subprocess import Popen, PIPE

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
from javax.swing.filechooser import FileNameExtensionFilter
#from java.awt.event import KeyListener;

from java.util import UUID
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
from org.sleuthkit.autopsy.casemodule import AddLocalFilesTask
from org.sleuthkit.autopsy.casemodule.services.FileManager import FileAddProgressUpdater
from org.sleuthkit.autopsy.ingest import ModuleContentEvent;

class ProgressUpdater(FileAddProgressUpdater):

    def __init__(self):
        self.files = []
        pass
    
    def fileAdded(self, newfile):
        self.files.append(newfile)
        #pass
        #progressBar.progress("Processing Recently Used Apps")	
        
    def getFiles(self):
        return self.files

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class VolatilityDumpIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Volatility Convert Hiber/Crash Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Convert Hiber/Crash files using Volatility"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return VolatilitySettingsWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, VolatilitySettingsWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return VolatilitySettingsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return VolatilityDumpIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class VolatilityDumpIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(VolatilityDumpIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.database_file = ""
        self.isAutodetect = False
        self.isProcessIds = False
        self.Process_Ids_To_Dump = ""
        self.Python_Program = False
        self.hiber_flag = False

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        #Show parameters that are passed in
        self.Volatility_Executable = self.local_settings.getVolatility_Directory()
        self.hiber_flag = self.local_settings.getFlag()
        
        self.log(Level.INFO, "Volatility Executable ==> " + self.local_settings.getVolatility_Directory())
        
        # Check to see if the file to execute exists, if it does not then raise an exception and log error
        # data is taken from the UI
        if 'vol.py' in self.Volatility_Executable:
            self.Python_Program = True
        if not os.path.exists(self.Volatility_Executable):
            raise IngestModuleException("colatility File to Run/execute does not exist.")
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process Hiberfil.sys and Crash Dumps")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Get the temp directory and create the sub directory
        if self.hiber_flag:
            Mod_Dir = Case.getCurrentCase().getModulesOutputDirAbsPath()
            try:
                ModOut_Dir = os.path.join(Mod_Dir, "Volatility\\Memory-Image-hiberfil")
                self.log(Level.INFO, "Module Output Directory ===>  " + ModOut_Dir)
                #dir_util.mkpath(ModOut_Dir)
                os.mkdir(Mod_Dir + "\\Volatility")
                os.mkdir(ModOut_Dir)
            except:
                self.log(Level.INFO, "***** Error Module Output Directory already exists " + ModOut_Dir)

            # Set the database to be read to the once created by the prefetch parser program
            skCase = Case.getCurrentCase().getSleuthkitCase();
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            files = fileManager.findFiles(dataSource, "hiberfil.sys", "/")
            numFiles = len(files)
            self.log(Level.INFO, "Number of files to process ==> " + str(numFiles))

            for file in files:
                self.log(Level.INFO, "File to process is ==> " + str(file))
                self.log(Level.INFO, "File name to process is ==> " + file.getName())
                tmp_Dir = Case.getCurrentCase().getTempDirectory()
                Hiber_File = os.path.join(tmp_Dir, file.getName())
                ContentUtils.writeToFile(file, File(Hiber_File))
                self.log(Level.INFO, "File name to process is ==> " + Hiber_File)
                # Create the directory to dump the hiberfil
                dump_file = os.path.join(ModOut_Dir, "Memory-Image-from-hiberfil.img")
                if self.Python_Program:    
                    self.log(Level.INFO, "Running program ==> " + self.Volatility_Executable + " imagecopy -f " + Hiber_File + " " + \
                             " -O " + dump_file)
                    pipe = Popen(["Python.exe", self.Volatility_Executable, "imagecopy", "-f", Hiber_File, "-O" + dump_file], stdout=PIPE, stderr=PIPE)
                else:
                    self.log(Level.INFO, "Running program ==> " + self.Volatility_Executable + " imagecopy -f " + Hiber_File + " " + \
                             " -O " + dump_file)
                    pipe = Popen([self.Volatility_Executable, "imagecopy", "-f", Hiber_File, "-O" + dump_file], stdout=PIPE, stderr=PIPE)
                out_text = pipe.communicate()[0]
                self.log(Level.INFO, "Output from run is ==> " + out_text)               
                
                # Add hiberfil memory image to a new local data source
                services = IngestServices.getInstance()
        
                progress_updater = ProgressUpdater()  
                newDataSources = []  

                dump_file = os.path.join(ModOut_Dir, "Memory-Image-from-hiberfil.img")            
                dir_list = []
                dir_list.append(dump_file)
             
                # skCase = Case.getCurrentCase().getSleuthkitCase();
                fileManager_2 = Case.getCurrentCase().getServices().getFileManager()
                skcase_data = Case.getCurrentCase()
            
                # Get a Unique device id using uuid
                device_id = UUID.randomUUID()
                self.log(Level.INFO, "device id: ==> " + str(device_id))

                skcase_data.notifyAddingDataSource(device_id)
                
                # Add data source with files
                newDataSource = fileManager_2.addLocalFilesDataSource(str(device_id), "Hiberfile Memory Image", "", dir_list, progress_updater)
                
                newDataSources.append(newDataSource.getRootDirectory())
               
                # Get the files that were added
                files_added = progress_updater.getFiles()
                #self.log(Level.INFO, "Fire Module1: ==> " + str(files_added))
                
                for file_added in files_added:
                    skcase_data.notifyDataSourceAdded(file_added, device_id)
                    self.log(Level.INFO, "Fire Module1: ==> " + str(file_added))
  
            
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "HiberFil_Crash", " Hiberfil/Crash Dumps have been extracted fro Image. " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
         
# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class VolatilitySettingsWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.Volatility_Dir_Found = False
        self.Volatility_Directory = ""
        self.Exclude_File_Sources = False
        self.hiber_flag = False
       
    def getVersionNumber(self):
        return serialVersionUID

    # Define getters and settings for data you want to store from UI
    def getFlag(self):
        return self.hiber_flag

    def setFlag(self, flag):
        self.hiber_flag = flag

    def getVolatility_Dir_Found(self):
        return self.Volatility_Dir_Found

    def setVolatility_Dir_Found(self, flag):
        self.Volatility_Dir_Found = flag

    def getVolatility_Directory(self):
        return self.Volatility_Directory

    def setVolatility_Directory(self, dirname):
        self.Volatility_Directory = dirname

    
# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class VolatilitySettingsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
    
           
    # Check to see if there are any entries that need to be populated from the database.        
    def check_Database_entries(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\GUI_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings DB!")
 
        try:
           stmt = dbConn.createStatement()
           SQL_Statement = 'Select Setting_Name, Setting_Value from settings;' 
           resultSet = stmt.executeQuery(SQL_Statement)
           while resultSet.next():
               if resultSet.getString("Setting_Name") == "Volatility_Executable_Directory":
                   self.Program_Executable_TF.setText(resultSet.getString("Setting_Value"))
                   self.local_settings.setVolatility_Directory(resultSet.getString("Setting_Value"))
                   self.local_settings.setVolatility_Dir_Found(True)
               # if resultSet.getString("Setting_Name") == "Volatility_Version":
                   # self.Version_CB.setSelectedItem(resultSet.getString("Setting_Value"))
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
           if (self.local_settings.getVolatility_Dir_Found()):
               SQL_Statement = 'Update settings set Setting_Value = "' + self.Program_Executable_TF.getText() + '"' + \
                               ' where setting_name = "Volatility_Executable_Directory";' 
               # SQL_Statement2 = 'Update settings set Setting_Value = "' + self.Version_CB.getSelectedItem() + '"' + \
                               # ' where setting_name = "Volatility_Version";' 
           else:
               SQL_Statement = 'Insert into settings (Setting_Name, Setting_Value) values ("Volatility_Executable_Directory", "' +  \
                               self.Program_Executable_TF.getText() + '");' 
               # SQL_Statement2 = 'Insert into settings (Setting_Name, Setting_Value) values ("Volatility_Version", "' +  \
                               # self.Version_CB.getSelectedItem() + '");' 
           
           stmt.execute(SQL_Statement)
           # stmt.execute(SQL_Statement2)
           self.Error_Message.setText("Volatility Executable Directory Saved")
           self.local_settings.setVolatility_Directory(self.Program_Executable_TF.getText())
        except SQLException as e:
           self.Error_Message.setText(e.getMessage())
        stmt.close()
        dbConn.close()
           
    # When button to find file is clicked then open dialog to find the file and return it.       
    def Find_Dir(self, e):

       chooseFile = JFileChooser()
       filter = FileNameExtensionFilter("All", ["*.*"])
       chooseFile.addChoosableFileFilter(filter)
       #chooseFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

       ret = chooseFile.showDialog(self.panel0, "Find Volatility Directory")

       if ret == JFileChooser.APPROVE_OPTION:
           file = chooseFile.getSelectedFile()
           Canonical_file = file.getCanonicalPath()
           #text = self.readPath(file)
           self.local_settings.setVolatility_Directory(Canonical_file)
           self.Program_Executable_TF.setText(Canonical_file)

    def keyPressed(self, event):
        self.local_settings.setProcessIDs(self.Process_Ids_To_Dump_TF.getText()) 
        #self.Error_Message.setText(self.Process_Ids_To_Dump_TF.getText())
        
    def checkBoxEvent(self, event):
        if self.Check_Box.isSelected():
            self.local_settings.setFlag(True)
        else:
            self.local_settings.setFlag(False)
        
    # Create the initial data fields/layout in the UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Error_Message = JLabel( "") 
        self.Error_Message.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 31
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints( self.Error_Message, self.gbcPanel0 ) 
        self.panel0.add( self.Error_Message ) 

        self.Label_1 = JLabel("Volatility Executable Directory")
        self.Label_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Label_1 ) 

        self.Program_Executable_TF = JTextField(10) 
        self.Program_Executable_TF.setEnabled(True)
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

        self.Find_Program_Exec_BTN = JButton( "Find Dir", actionPerformed=self.Find_Dir)
        self.Find_Program_Exec_BTN.setEnabled(True)
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

        self.Blank_1 = JLabel( " ") 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_1, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_1 ) 

        self.Save_Settings_BTN = JButton( "Save Volatility Exec Dir", actionPerformed=self.SaveSettings) 
        self.Save_Settings_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Save_Settings_BTN ) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Save_Settings_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Save_Settings_BTN ) 

        self.Blank_2 = JLabel( " ") 
        self.Blank_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_2, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_2 ) 

        self.Blank_3 = JLabel( " ") 
        self.Blank_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 13
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_3, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_3 ) 

        self.Check_Box = JCheckBox("Extract and Create Memory Image from Hiberfile", actionPerformed=self.checkBoxEvent) 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Check_Box, self.gbcPanel0 ) 
        self.panel0.add( self.Check_Box ) 

        self.Blank_4 = JLabel( " ") 
        self.Blank_4.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 17
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_4, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_4 ) 

        self.Blank_5 = JLabel( " ") 
        self.Blank_5.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 21
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_5, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_5 ) 

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

        self.Label_3 = JLabel( "Message:") 
        self.Label_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 29
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_3, self.gbcPanel0 ) 
        self.panel0.add( self.Label_3 ) 
		
        self.add(self.panel0)

    # Custom load any data field and initialize the values
    def customizeComponents(self):
        self.Check_Box.setSelected(self.local_settings.getFlag())
        self.check_Database_entries()
        #pass
        
    # Return the settings used
    def getSettings(self):
        return self.local_settings

