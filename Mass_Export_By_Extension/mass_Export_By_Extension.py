# This python autopsy module will Export all files based on user supplied extensions
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

# mass_export_by_extension.
# February 2020
# 
# Comments 
#   Version 1.0 - Initial version - February 2020
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
class MassExportByExtensionIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Mass Export By Extension"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Mass Export Of Files By Extension"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return MassExportByExtensionSettingsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return MassExportByExtensionIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class MassExportByExtensionIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(MassExportByExtensionIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        extensionListTemp = self.local_settings.getSetting('fileExtension')
        self.extensionList = extensionListTemp.split(",")

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        #Show parameters that are passed in
        self.log(Level.INFO, "extensionList  =====>" + str(self.extensionList))
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process")

        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
		# Create Event Log directory in temp directory, if it exists then continue on processing		
        exportDirectory = Case.getCurrentCase().getExportDirectory()
        exportDir = os.path.join(exportDirectory, "Mass_Export")

        self.log(Level.INFO, "create Directory " + exportDir)
        try:
            os.mkdir(exportDir)
        except:
            self.log(Level.INFO, "Mass Export directory already exists" + exportDir)
            
        for fileExtension in self.extensionList:
            fileExt = fileExtension.strip()
            files = fileManager.findFiles(dataSource, "%." + fileExt)
            numFiles = len(files)
            self.log(Level.INFO, "found " + str(numFiles) + " files for extension ==> " + str(fileExtension))

            expDir = os.path.join(exportDir, fileExt)
            try: 
                os.mkdir(expDir)
            except:
                self.log(Level.INFO, "Directory already exists ==> " + str(expDir))
            
            for file in files:
                #self.log(Level.INFO, 'Parent Path is ==> ' + file.getParentPath())
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                try:
                    #self.log(Level.INFO, "Writing file ==> " + file.getName())
                    extractedFile = os.path.join(expDir, str(file.getId()) + "-" + file.getName())
                    ContentUtils.writeToFile(file, File(extractedFile))
                except:
                    self.log(Level.INFO, "Error writing File " + os.path.join(temporaryDirectory, file.getName()))
                

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Mass Export By Extension Complete",  "Complete" )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
# UI that is shown to user for each ingest job so they can configure the job.
class MassExportByExtensionSettingsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
            
    def setFileExtension(self, event):
        self.local_settings.setSetting('fileExtension', self.fileExtension_TF.getText()) 

    # Create the initial data fields/layout in the UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Label_2 = JLabel("List of File Extensions to Export, Comma Seperated no dots (.)")
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

        self.fileExtension_TF = JTextField(30, focusLost=self.setFileExtension) 
        self.fileExtension_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.fileExtension_TF, self.gbcPanel0 ) 
        self.panel0.add( self.fileExtension_TF ) 

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



        self.add(self.panel0)

    # Custom load any data field and initialize the values
    def customizeComponents(self):
        self.fileExtension_TF.setText(self.local_settings.getSetting('fileExtension')) 

    # Return the settings used
    def getSettings(self):
        return self.local_settings
