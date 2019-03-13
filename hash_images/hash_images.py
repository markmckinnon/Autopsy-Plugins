# This python autopsy module will hash non E01 images
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

# hash_images module to hash non e01 images.
# April 2018
# 
# Comments 
#   Version 1.0 - Initial version - August 2018
# 

import jarray
import inspect
import os
import hashlib

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
#from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from java.util import ArrayList
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
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
class HashImagesIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Hash_Images"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Hash Non E01 Images"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def hasIngestJobSettingsPanel(self):
        return True

    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return HashImageSettingsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return HashImagesIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class HashImagesIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(HashImagesIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")
        self.MD5HashToCheck = ""
        self.SHA1HashToCheck = ""
        self.FTKLogFile = ""

    def startUp(self, context):
        self.context = context
        self.FTKLogFile = self.local_settings.getSetting('FTKLogFile')
        self.MD5HashToCheck = self.local_settings.getSetting('MD5Hash')
        self.SHA1HashToCheck = self.local_settings.getSetting('SHA1Hash')
        self.log(Level.INFO, "Settings ==> " + str( self.MD5HashToCheck) + " <> " + str( self.SHA1HashToCheck))
        self.log(Level.INFO, "Settings ==> " + str(len(self.MD5HashToCheck)) + " <> " + str(len(self.SHA1HashToCheck)))
        pass
 
    def getFTKHashs(self, fileName):

        hashDict = {}
        
        with open(fileName, "r") as f:
            txtLine = f.readline()
            while txtLine:
                print (txtLine)
                if "MD5" in txtLine:
                   hashLine = txtLine.split(":")
                   if len(hashLine) > 2:
                       hashDict["Verify MD5"] = hashLine[1].strip()
                   else:
                       hashDict["Computed MD5"] = hashLine[1].strip()
                elif "SHA1" in txtLine:
                   hashLine = txtLine.split(":")
                   if len(hashLine) > 2:
                       hashDict["Verify SHA1"] = hashLine[1].strip()
                   else:
                       hashDict["Computed SHA1"] = hashLine[1].strip()
                txtLine = f.readline()
         
        self.log(Level.INFO, "Hashs found in File ==> " + str(hashDict))         
        return hashDict 

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

    
        FTKHashValues = {}
        if (self.FTKLogFile != None):
            FTKHashValues = self.getFTKHashs(self.FTKLogFile)
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        #progressBar.switchToDeterminate(numFiles)
        
        hashMd5 = hashlib.md5()
        hashSha1 = hashlib.sha1()
        
        hashImages = dataSource.getPaths()
    
        imgType = dataSource.getType()
        
        self.log(Level.INFO, "Image Type ==> " + str(imgType))

        if ((imgType == TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_RAW_SING) or \
            (imgType == TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_RAW_SPLIT) or \
            (imgType == TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_VHD_VHD) or \
            (imgType == TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_VMDK_VMDK)): 
        
            for fileName in hashImages:

                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "filename ==> " + fileName)
                with open(fileName, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hashSha1.update(chunk)
                        hashMd5.update(chunk)
        
            self.log(Level.INFO, "MD5 Hash is " + str(hashMd5.hexdigest()))
            self.log(Level.INFO, "sha1 Hash is " + str(hashSha1.hexdigest()))
            
            if len(FTKHashValues) > 0:
                if ((FTKHashValues['Computed MD5'] in str(hashMd5.hexdigest())) and \
                    (FTKHashValues['Verify MD5'] in str(hashMd5.hexdigest())) and \
                    (FTKHashValues['Computed SHA1'] in str(hashSha1.hexdigest())) and \
                    (FTKHashValues['Verify SHA1'] in str(hashSha1.hexdigest()))):
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, \
                         "Hash Images processed", " Hash Images verified by FTK Imager Log " + self.FTKLogFile)
                    IngestServices.getInstance().postMessage(message)
                else:
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, \
                         "Hash Images processed", " Hash Images NOT verified by FTK Imager Log" + self.FTKLogFile)
                    IngestServices.getInstance().postMessage(message)
                return IngestModule.ProcessResult.OK
            elif len(self.MD5HashToCheck) > 0:
                self.log(Level.INFO, "MD5 Hash Provided ")
                if (self.MD5HashToCheck in hashMd5.hexdigest()):
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, \
                         "Hash Images processed", " Hash Images - verified by supplied Value MD5 " + str(hashMd5.hexdigest()))
                    IngestServices.getInstance().postMessage(message)
                else:
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, \
                         "Hash Images processed", " Hash Images - NOT verified by supplied Value MD5 " + str(hashMd5.hexdigest()))
                    IngestServices.getInstance().postMessage(message)
                return IngestModule.ProcessResult.OK
            elif len(self.SHA1HashToCheck) > 0:
                self.log(Level.INFO, "SHA1 Provided ")
                if (self.SHA1HashToCheck in hashSha1.hexdigest()):
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, \
                         "Hash Images processed", " Hash Images - verified by supplied Value SHA1 " + str(hashSha1.hexdigest()))
                    IngestServices.getInstance().postMessage(message)
                else:
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, \
                         "Hash Images processed", " Hash Images - NOT verified by supplied Value SHA1 " + str(hashSha1.hexdigest()))
                    IngestServices.getInstance().postMessage(message)
                return IngestModule.ProcessResult.OK
            else:
                self.log(Level.INFO, "no hashes provided ")
                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, \
                "Hash Images processed", " Hash Images - NO valid MD5/SHA1 provided to compare " + str(hashMd5.hexdigest()))
                IngestServices.getInstance().postMessage(message)
                return IngestModule.ProcessResult.OK
                
        else:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Hash_Images", "Skipping Non RAW, VHD, VMDK image " + str(hashImages[0]) )
            IngestServices.getInstance().postMessage(message)

            return IngestModule.ProcessResult.OK                
        
# UI that is shown to user for each ingest job so they can configure the job.
class HashImageSettingsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
        self.initComponents()
        self.customizeComponents()
    
    def FindFTKTxtFile(self, e):

       chooseFile = JFileChooser()
       filter = FileNameExtensionFilter("ALL", ["*.*"])
       chooseFile.addChoosableFileFilter(filter)

       ret = chooseFile.showDialog(self.panel0, "Find FTK Log File")
       
       if ret == JFileChooser.APPROVE_OPTION:
           file = chooseFile.getSelectedFile()
           Canonical_file = file.getCanonicalPath()
           #text = self.readPath(file)
           self.local_settings.setSetting('FTKLogFile', Canonical_file)
           setSetting('FTKLogFile', Canonical_file)
           self.FTKLogFile_TF.setText(Canonical_file)

    def keyPressedMD5(self, event):  
        self.local_settings.setSetting('MD5Hash', self.MD5HashValue_TF.getText())

    def keyPressedSHA1(self, event):  
        self.local_settings.setSetting('SHA1Hash', self.SHA1HashValue_TF.getText())

    # Create the initial data fields/layout in the UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Label_1 = JLabel("MD5 Hash Value To Verify")
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

        self.MD5HashValue_TF = JTextField(20, focusLost=self.keyPressedMD5) 
        self.MD5HashValue_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.MD5HashValue_TF, self.gbcPanel0 ) 
        self.panel0.add( self.MD5HashValue_TF ) 

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

        self.Label_2 = JLabel("SHA1 Hash Value To Verify")
        self.Label_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_2, self.gbcPanel0 ) 
        self.panel0.add( self.Label_2 ) 

        self.SHA1HashValue_TF = JTextField(20, focusLost=self.keyPressedSHA1) 
        self.SHA1HashValue_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.SHA1HashValue_TF, self.gbcPanel0 ) 
        self.panel0.add( self.SHA1HashValue_TF ) 

        self.Blank_2 = JLabel( " ") 
        self.Blank_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_1, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_1 ) 

        self.Label_3 = JLabel("FTK Log File")
        self.Label_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 13 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_3, self.gbcPanel0 ) 
        self.panel0.add( self.Label_3 ) 

        self.FTKLogFile_TF = JTextField(20) 
        self.FTKLogFile_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.FTKLogFile_TF, self.gbcPanel0 ) 
        self.panel0.add( self.FTKLogFile_TF ) 

        self.FTKLogFile_BTN = JButton( "Find File", actionPerformed=self.FindFTKTxtFile)
        self.FTKLogFile_BTN.setEnabled(True)
        self.rbgPanel0.add( self.FTKLogFile_BTN ) 
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 15 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.FTKLogFile_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.FTKLogFile_BTN ) 

        self.Label_4 = JLabel( "Message:") 
        self.Label_4.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 29
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_4, self.gbcPanel0 ) 
        self.panel0.add( self.Label_4 ) 
		
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

        self.add(self.panel0)

    # Custom load any data field and initialize the values
    def customizeComponents(self):
        pass
        
    # Return the settings used
    def getSettings(self):
        self.local_settings.setSetting('MD5Hash', self.MD5HashValue_TF.getText())
        self.local_settings.setSetting('SHA1Hash', self.SHA1HashValue_TF.getText())
        return self.local_settings

