# This python autopsy module will import a plaso file.  It will ask the user
# for the directory where the plaso executables reside then it will convert the plaso
# storage file into a SQLite database then it will ask what to import then import
# thoses records.
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

# Plaso_ImportSettings with settings module.
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
from javax.swing import JTextField
from javax.swing import JLabel
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
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
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
class Plaso_ImportIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Plaso Import Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Import Plaso Storage File"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return Plaso_ImportSettingsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return Plaso_ImportIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class Plaso_ImportIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(Plaso_ImportIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        #self.List_Of_Plaso_ImportSettings = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        #Show parameters that are passed in
        self.log(Level.INFO, "Plaso directory ==> " + self.local_settings.getSetting('Plaso_Directory'))
        self.log(Level.INFO, "Plaso Storage File ==> " + self.local_settings.getSetting('Plaso_Storage_File'))
        self.exclude_file_sources = self.local_settings.getSetting('Exclude_File_Sources')
        if self.local_settings.getSetting('Exclude_File_Sources') == 'true':
            self.log(Level.INFO, "Exclude File Information from import process")
            self.exclude_file_sources = True
        else:
            self.log(Level.INFO, "Include File Information in import process")
            self.exclude_file_sources = False
        
        # Create path to plaso storage file
        self.path_to_storage_file = self.local_settings.getSetting('Plaso_Storage_File')
        
        # Check to see if the file to execute exists, if it does not then raise an exception and log error
        # data is taken from the UI
        self.path_to_exe = os.path.join(self.local_settings.getSetting('Plaso_Directory'), "psort.exe")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("Psort File to Run/execute does not exist.")
        
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
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, ".", "/")
        numFiles = len(files)
        #self.log(Level.INFO, "Number of files found " + str(numFiles) + " files")
        #self.log(Level.INFO, "found " + str(files) + " files")
        # progressBar.switchToDeterminate(numFiles)
        # fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        #Temp_Dir = Case.getCurrentCase().getTempDirectory()
        Temp_Dir = Case.getCurrentCase().getModulesOutputDirAbsPath()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Plaso_Import")
        except:
		    self.log(Level.INFO, "Plaso Import Directory already exists " + Temp_Dir)
			
        # Run the psort.exe program against the storage file to convert the storage file from native to SQLite 
        self.database_file = Temp_Dir + "\\Plaso_Import\\Plaso_Import.db3"
        self.log(Level.INFO, "Running program ==> " + self.path_to_exe + " -o 4n6time_sqlite -w " + Temp_Dir + "\\Plaso_Import\\" + \
                 "plaso_import.db3 " + self.local_settings.getSetting('Plaso_Storage_File'))
        pipe = Popen([self.path_to_exe, "-o", "4n6time_sqlite", "-w", self.database_file, self.path_to_storage_file], stdout=PIPE, stderr=PIPE)
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text)               
    
        plaso_db_file = Temp_Dir + "\Plaso_Import\Plaso_Import.db3"
        plaso_db_dir = Temp_Dir + "\Plaso_Import"
        self.log(Level.INFO, "Plaso DB File ==> " + plaso_db_file)
        for file in files:
            abstract_file_info = skCase.getAbstractFileById(file.getId())
            #self.log(Level.INFO, "Abstract File Info ==> " + str(abstract_file_info))
        
        # Add dervived file
        file = skCase.addDerivedFile("Plaso_Import.db3", plaso_db_file, os.path.getsize(plaso_db_file), + \
                                     0, 0, 0, 0, True, abstract_file_info, "", "", "", "", TskData.EncodingType.NONE)
        
        self.log(Level.INFO, "Derived File ==> " + str(file))
        
        # Create the Attributes for plaso
        try:
           attID_source = skCase.addArtifactAttributeType("TSK_PLASO_SOURCE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Plaso Source")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Plaso Source ==> ")
        try:
           attID_sourcetype = skCase.addArtifactAttributeType("TSK_PLASO_SOURCE_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Plaso Source Type")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Plaso Source Type ==> ")
        try:
           attID_type = skCase.addArtifactAttributeType("TSK_PLASO_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Plaso Type")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Plaso Type ==> ")
        try:
           attID_desc = skCase.addArtifactAttributeType("TSK_PLASO_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Plaso Description")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Plaso Description ==> ")
        try:
           attID_filename = skCase.addArtifactAttributeType("TSK_PLASO_FILENAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Plaso File Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Plaso File Name ==> ")
        try:
           attID_format = skCase.addArtifactAttributeType("TSK_PLASO_FORMAT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Plaso Format")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Plaso Format ==> ")
        try:
           attID_extra = skCase.addArtifactAttributeType("TSK_PLASO_EXTRA", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Plaso Extra")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Plaso Extra ==> ")
        try:
           attID_vss_num = skCase.addArtifactAttributeType("TSK_PLASO_VSS_STORE_NUM", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Plaso VSS Store Num")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Plaso VSS Store Num ==> ")

        # Get the artifact and attributes
        attID_source = skCase.getAttributeType("TSK_PLASO_SOURCE")
        artID_sourcetype = skCase.getAttributeType("TSK_PLASO_SOURCE_TYPE")
        attID_type = skCase.getAttributeType("TSK_PLASO_TYPE")
        attID_desc = skCase.getAttributeType("TSK_PLASO_DESCRIPTION")
        self.log(Level.INFO, "Description Attribute ==> " + str(attID_desc))
        attID_filename = skCase.getAttributeType("TSK_PLASO_FILENAME")
        attID_format = skCase.getAttributeType("TSK_PLASO_FORMAT")
        attID_extra = skCase.getAttributeType("TSK_PLASO_EXTRA")
        attID_vss_num = skCase.getAttributeType("TSK_PLASO_VSS_STORE_NUM")

        # Open the DB using JDBC
        lclDbPath = os.path.join(plaso_db_dir, "Plaso_Import.db3")
        self.log(Level.INFO, "Path the Plaso Import file database file created ==> " + lclDbPath)
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file (not SQLite) plaso_Import.db3 (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
        
        # Query the l2t_sources table to include or exclude FILES based on user response 
        try:
           stmt = dbConn.createStatement()
           l2t_sources_sql = "select sources from l2t_sources"
           if self.exclude_file_sources:
               l2t_sources_sql = l2t_sources_sql + " where sources != 'FILE'"
           self.log(Level.INFO, l2t_sources_sql)
           resultSet = stmt.executeQuery(l2t_sources_sql)
           self.log(Level.INFO, "query l2t_sources table")
        except SQLException as e:
           self.log(Level.INFO, "Error querying database for l2t_sources table (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK

        # Cycle through each row and create artifacts
        while resultSet.next(): 
            # Create the safari last session artifact
            try:
                 self.log(Level.INFO, "Begin Create New Artifacts ==> " + resultSet.getString("sources"))
                 artID_art = skCase.addArtifactType( "TSK_PLASO" + resultSet.getString("sources"), "Plaso Source " + \
                                                    resultSet.getString("sources"))
            except:		
                 self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

            # Get the artifact and attributes
            artID_art = skCase.getArtifactTypeID("TSK_PLASO" + resultSet.getString("sources"))
            artID_art_evt = skCase.getArtifactType("TSK_PLASO" + resultSet.getString("sources"))

            try:
               stmt = dbConn.createStatement()
               log2timeline_sql = "select source, sourcetype, type, description, filename, format, extra, " + \
                                  " strftime('%s',datetime) 'datetime', vss_store_number, url " + \
                                  " from log2timeline where source = '" + resultSet.getString("sources") + "';"
               self.log(Level.INFO, log2timeline_sql)
               resultSet2 = stmt.executeQuery(log2timeline_sql)
               self.log(Level.INFO, "query lastsession table")
            except SQLException as e:
               self.log(Level.INFO, "Error querying database for log2timeline table (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK

           # Cycle through each row and create artifacts
            while resultSet2.next():
               try: 
                   art = file.newArtifact(artID_art)
                   #self.log(Level.INFO, "Inserting attribute source ==> 2")
                   art.addAttribute(BlackboardAttribute(artID_sourcetype, Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("source")))
                   #self.log(Level.INFO, "Inserting attribute sourcetype")
                   art.addAttribute(BlackboardAttribute(artID_sourcetype, Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("sourcetype")))
                   #self.log(Level.INFO, "Inserting attribute Type")
                   art.addAttribute(BlackboardAttribute(attID_type, Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("type")))
                   #self.log(Level.INFO, "Inserting attribute description")
                   art.addAttribute(BlackboardAttribute(attID_desc, Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("description")))
                   #self.log(Level.INFO, "Inserting attribute filename")
                   art.addAttribute(BlackboardAttribute(attID_filename, Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("filename")))
                   #self.log(Level.INFO, "Inserting attribute format")
                   art.addAttribute(BlackboardAttribute(attID_format, Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("format")))
                   #self.log(Level.INFO, "Inserting attribute extra")
                   art.addAttribute(BlackboardAttribute(attID_extra, Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("extra")))
                   #self.log(Level.INFO, "Inserting attribute Date/Time")
                   art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getInt("datetime")))
                   #self.log(Level.INFO, "Inserting attribute vss_store_number")
                   art.addAttribute(BlackboardAttribute(attID_vss_num, Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("vss_store_number")))
                   #self.log(Level.INFO, "Inserting attribute URL")
                   art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), Plaso_ImportIngestModuleFactory.moduleName, resultSet2.getString("URL")))

               except SQLException as e:
                   self.log(Level.INFO, "Error getting values from the Log2timeline table (" + e.getMessage() + ")")

            IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(Plaso_ImportIngestModuleFactory.moduleName, artID_art_evt, None))

        # stmt.close()
        # dbConn.close()

        # Clean up
        #os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        # for file in files:
           # try:
              # os.remove(Temp_Dir + "\\" + file.getName())
           # except:
              # self.log(Level.INFO, "removal of Safari lastsession file failed " + Temp_Dir + "\\" + file.getName())
        # try:
           # os.rmdir(Temp_Dir)		
        # except:
		   # self.log(Level.INFO, "removal of Safari session directory failed " + Temp_Dir)
        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Plaso_ImportSettings", " Plaso_ImportSettings Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		


# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class Plaso_ImportSettingsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
    
    # Check the checkboxs to see what actions need to be taken
    def checkBoxEvent(self, event):
        if self.Exclude_File_Sources_CB.isSelected():
            self.local_settings.setSetting('Exclude_File_Sources', 'true')
        else:
            self.local_settings.setSetting('Exclude_File_Sources', 'false')

    # When button to find file is clicked then open dialog to find the file and return it.       
    def Find_Plaso_Dir(self, e):

       chooseFile = JFileChooser()
       filter = FileNameExtensionFilter("All", ["*.*"])
       chooseFile.addChoosableFileFilter(filter)
       chooseFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

       ret = chooseFile.showDialog(self.panel0, "Find Plaso Directory")

       if ret == JFileChooser.APPROVE_OPTION:
           file = chooseFile.getSelectedFile()
           Canonical_file = file.getCanonicalPath()
           #text = self.readPath(file)
           self.local_settings.setSetting('Plaso_Directory', Canonical_file)
           self.Program_Executable_TF.setText(Canonical_file)

    def Find_Plaso_File(self, e):

       chooseFile = JFileChooser()
       filter = FileNameExtensionFilter("All", ["*.*"])
       chooseFile.addChoosableFileFilter(filter)

       ret = chooseFile.showDialog(self.panel0, "Find Plaso Storage File")

       if ret == JFileChooser.APPROVE_OPTION:
           file = chooseFile.getSelectedFile()
           Canonical_file = file.getCanonicalPath()
           #text = self.readPath(file)
           self.local_settings.setSetting('Plaso_Storage_File', Canonical_file)
           self.Plaso_Storage_File_TF.setText(Canonical_file)

    def setPlasoDirectory(self, event):
        self.local_settings.setSetting('Plaso_Directory', self.Program_Executable_TF.getText()) 
           
    def setPlasoStorageFile(self, event):
        self.local_settings.setSetting('Plaso_Storage_File', self.Plaso_Storage_File_TF.getText()) 
           
    # Create the initial data fields/layout in the UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Label_1 = JLabel("Plaso Executable Directory")
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

        self.Program_Executable_TF = JTextField(20, focusLost=self.setPlasoDirectory) 
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

        self.Find_Program_Exec_BTN = JButton( "Find Dir", actionPerformed=self.Find_Plaso_Dir)
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

        self.Label_1 = JLabel("Plaso Storage File")
        self.Label_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Label_1 ) 

        self.Plaso_Storage_File_TF = JTextField(20, focusLost=self.setPlasoStorageFile) 
        self.Plaso_Storage_File_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Plaso_Storage_File_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Plaso_Storage_File_TF ) 

        self.Find_Storage_BTN = JButton( "Find Storage File", actionPerformed=self.Find_Plaso_File)
        self.Find_Storage_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Find_Storage_BTN ) 
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Find_Storage_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Find_Storage_BTN ) 

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

        self.Exclude_File_Sources_CB = JCheckBox( "Exclude File Source", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Exclude_File_Sources_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Exclude_File_Sources_CB ) 

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

        self.Label_3 = JLabel( "Message:") 
        self.Label_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 19
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_3, self.gbcPanel0 ) 
        self.panel0.add( self.Label_3 ) 
		
        self.Error_Message = JLabel( "") 
        self.Error_Message.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 23
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
        self.Exclude_File_Sources_CB.setSelected(self.local_settings.getSetting('Exclude_File_Sources') == 'true')
        self.Program_Executable_TF.setText(self.local_settings.getSetting('Plaso_Directory'))
        self.Plaso_Storage_File_TF.setText(self.local_settings.getSetting('Plaso_Storage_File'))

    # Return the settings used
    def getSettings(self):
        return self.local_settings

