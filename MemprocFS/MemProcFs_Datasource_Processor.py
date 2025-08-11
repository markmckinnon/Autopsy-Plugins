# This module helps to process Memory images using MemProcFS
#
# Contact: Mark McKinnon [mark <dot> McKinnon <at> gmail [dot] Com]
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

# Simple data source Processor-level module for Autopsy.
#
#    Version 1.0 - Initial - Aug 2025

import inspect
import os
import threading
from subprocess import Popen, PIPE

from java.util import UUID
from java.util.logging import Level
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.beans import PropertyChangeSupport
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JFileChooser
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JTextField
from javax.swing import JComboBox
from javax.swing.filechooser import FileNameExtensionFilter

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule import AddLocalFilesTask
from org.sleuthkit.autopsy.casemodule.services.FileManager import FileAddProgressUpdater
from org.sleuthkit.autopsy.corecomponentinterfaces import DataSourceProcessor
from org.sleuthkit.autopsy.corecomponentinterfaces import DataSourceProcessorCallback
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.datasourceprocessors import DataSourceProcessorAdapter  

class MemProcFsDSPProcessor(DataSourceProcessorAdapter):
    configPanel = None
    moduleName = "MemProcFS Process Memory Image"

    def __init__(self):
        self.configPanel = DataSourcesPanelSettings()
    
    @staticmethod
    def getType():
        return MemProcFsDSPProcessor.moduleName

    def getDataSourceType(self):
        return self.moduleName

    def getPanel(self):
        return self.configPanel

    def isPanelValid(self):
        return self.configPanel.validatePanel()

    def run(self, host, progressMonitor, callback):
        self.configPanel.run(host, progressMonitor, callback)

    #Overrides not used
    def cancel(self):
        pass

    #Overrides not used
    def reset(self):
        pass

class ProgressUpdater(FileAddProgressUpdater):
    def __init__(self):
        self.files = []
        pass
    
    def fileAdded(self, newfile):
        self.files.append(newfile)
        
    def getFiles(self):
        return self.files

class DataSourcesPanelSettings(JPanel):
    serialVersionUID = 1

    _logger = Logger.getLogger(MemProcFsDSPProcessor.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.pcs = PropertyChangeSupport(self)
        self.initComponents()
        self.validPanel = True
        
    def getVersionNumber(self):
        return serialVersionUID

    #PROCESSOR LOGIC
    def run(self, host, progressMonitor, callback):
        threading.Thread(target=self.running, args=[progressMonitor, callback]).start()

    def running(self, progressMonitor, callback):
        result = DataSourceProcessorCallback.DataSourceProcessorResult.NO_ERRORS
        progressMonitor.setIndeterminate(True)
        progress_updater = ProgressUpdater()  
        data_sources = []
        errors = []

        # Setup Directories
        progressMonitor.setProgressText('\tProcessing Memory Image {}\n\tWith MemProcFS\n\tPlease wait.'.format(self.memory_file_TF.getText()))
        file_path, file_name = os.path.split(self.memory_file_TF.getText())
        out_path = os.path.join(Case.getCurrentCase().getModuleDirectory(), 'MemProcFS')
        file_path = os.path.join(out_path, "MemprocFS" ,"files", "ROOT") 

        dataSources = []
        dataSources.append(file_path)
        dataSources.append(out_path)
        
        if not os.path.exists(out_path):
            os.makedirs(out_path)

        # Extract memory Image
        pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parse-memory-fs.exe")
        self.log(Level.INFO, "Running program ==> " + pathToExe + " -f " + self.memory_file_TF.getText() + " -od " + out_path)
        pipe = Popen([pathToExe, "-f", self.memory_file_TF.getText(), "-od", out_path], stdout=PIPE, stderr=PIPE) 
        outText = pipe.communicate()[0]

        # Display output from parsing memory
        self.log(Level.INFO, "output from parse-memory-fs => " + outText)        

        for dataSource in dataSources:        

            # Get a Unique device id using uuid
            device_id = UUID.randomUUID()

            # Get current case and file manager
            skcase_data = Case.getCurrentCase()
            fileManager = Case.getCurrentCase().getServices().getFileManager()

            # Tell case we are adding data to the data source
            skcase_data.notifyAddingDataSource(device_id)

            # Update progress bar
            progressMonitor.setProgressText('\tAdding Files to Case from directory {}\n\tPlease wait.'.format(dataSource))

            # Add data source with files
            dir_list = []
            dir_list.append(dataSource)
            data_source = fileManager.addLocalFilesDataSource(str(device_id), file_name, "", dir_list, progress_updater)
            
            data_sources.append(data_source.getRootDirectory())
           
            # Get the files that were added
            files_added = progress_updater.getFiles()
            
            # Add files to the data source
            for file_added in files_added:
                skcase_data.notifyDataSourceAdded(file_added, device_id)
               #progressMonitor.setProgressText('\tAdding File{}\n\tPlease wait.'.format(file_added.getName()))

        callback.done(result, errors, data_sources)

    def validatePanel(self):
        return self.validPanel

    # When button to find file is clicked then open dialog to find the file and return it.       
    def Find_File(self, e):

       chooseFile = JFileChooser()
       filter = FileNameExtensionFilter("All", ["*."])
       chooseFile.addChoosableFileFilter(filter)
       chooseFile.setFileSelectionMode(JFileChooser.FILES_ONLY)
       
       ret = chooseFile.showDialog(self.panel0, "Find Memory Image")

       if ret == JFileChooser.APPROVE_OPTION:
           file = chooseFile.getSelectedFile()
           canonical_file = file.getCanonicalPath()
           self.memory_file_TF.setText(canonical_file)
           if (".dmp" in canonical_file.lower() or ".img" in canonical_file.lower()):
               self.validPanel = True
               self.pcs.firePropertyChange(DataSourceProcessor.DSP_PANEL_EVENT.UPDATE_UI.toString(), False, True)
           else:
               self.validPanel = False           
               self.pcs.firePropertyChange(DataSourceProcessor.DSP_PANEL_EVENT.UPDATE_UI.toString(), True, False)

    def initComponents(self):

        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Error_Message = JLabel( "") 
        self.Error_Message.setEnabled(True)
        self.gbcPanel0.gridx = 0
        self.gbcPanel0.gridy = 31
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints( self.Error_Message, self.gbcPanel0 ) 
        self.panel0.add( self.Error_Message ) 

        self.Label_1 = JLabel("Memory Image")
        self.Label_1.setEnabled(True)
        self.gbcPanel0.gridx = 0 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Label_1 ) 

        self.memory_file_TF = JTextField(30) 
        self.memory_file_TF.setEnabled(True)
        self.gbcPanel0.gridx = 0 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.memory_file_TF, self.gbcPanel0 ) 
        self.panel0.add( self.memory_file_TF ) 

        self.Find_memory_file_BTN = JButton( "Find File", actionPerformed=self.Find_File)
        self.Find_memory_file_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Find_memory_file_BTN ) 
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Find_memory_file_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Find_memory_file_BTN ) 

        self.Blank_3 = JLabel( "") 
        self.Blank_3.setEnabled(True)
        self.gbcPanel0.gridx = 0 
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_3, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_3 ) 

        self.add(self.panel0)

