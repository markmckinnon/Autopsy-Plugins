# This python autopsy module is several windows plugin modules that have been 
# combined to create one plugin that has check boxes to pick which one(s) you want
# to run
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

# Windows_Internals module.
# March 2017
# 
# Comments 
#   Version 1.0 - Initial version - March 2017
#   Version 1.1 - Added code for File History module - April 2017
# 

import jarray
import inspect
import os
import shutil
from subprocess import Popen, PIPE

from javax.swing import JCheckBox
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JFileChooser
from javax.swing import JScrollPane
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
class Windows_InternalsIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Windows Internals"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Windows Internals"
    
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
        return Windows_InternalsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return Windows_InternalsIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class Windows_InternalsIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(Windows_InternalsIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_Windows_Internals = []
        self.List_Of_tables = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        if self.local_settings.getSetting('Recentlyused_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "Recently Used ==> " + str(self.local_settings.getSetting('Recentlyused_Flag')))
                self.path_to_Recentlyused_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "show_ccm_recentlyusedapps.exe")
                if not os.path.exists(self.path_to_Recentlyused_file):
                   raise IngestModuleException("Recentlyused Executable does not exist for Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "Recently Used ==> " + str(self.local_settings.getSetting('Recentlyused_Flag')))
                self.path_to_Recentlyused_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "show_CCM_RecentlyUsedApps")
                if not os.path.exists(self.path_to_Recentlyused_file):
                   raise IngestModuleException("Recentlyused Executable does not exist for Linux")

        if self.local_settings.getSetting('Filehistory_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "File Hsitory ==> " + str(self.local_settings.getSetting('Filehistory_Flag')))
                self.path_to_Filehistory_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Export_FileHistory.exe")
                if not os.path.exists(self.path_to_Filehistory_file):
                   raise IngestModuleException("Export_Filehistory Executable does not exist for Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "File Hsitory ==> " + str(self.local_settings.getSetting('Filehistory_Flag')))
                self.path_to_Filehistory_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Export_FileHistory")
                if not os.path.exists(self.path_to_Filehistory_file):
                   raise IngestModuleException("Export_Filehistory Executable does not exist for Liniux")

        if self.local_settings.getSetting('Jumplist_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "Jumplist ==> " + str(self.local_settings.getSetting('Jumplist_Flag')))
                self.path_to_Jumplist_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_jl_ad.exe")
                if not os.path.exists(self.path_to_Jumplist_file):
                   raise IngestModuleException("Jumplist Executable does not exist for Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "Jumplist ==> " + str(self.local_settings.getSetting('Jumplist_Flag')))
                self.path_to_Jumplist_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Export_JL_Ad")
                if not os.path.exists(self.path_to_Jumplist_file):
                   raise IngestModuleException("Jumplist Executable does not exist fro Linux")

        if self.local_settings.getSetting('Prefetch_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "Prefetch ==> " + str(self.local_settings.getSetting('Prefetch_Flag')))
                self.path_to_Prefetch_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parse_prefetch.exe")
                if not os.path.exists(self.path_to_Prefetch_file):
                   raise IngestModuleException("Prefetch Executable does not exist for Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "Prefetch ==> " + str(self.local_settings.getSetting('Prefetch_Flag')))
                self.path_to_Prefetch_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parse_prefetch")
                if not os.path.exists(self.path_to_Prefetch_file):
                   raise IngestModuleException("Prefetch Executable does not exist for Linux")

        if self.local_settings.getSetting('SAM_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "SAM ==> " + str(self.local_settings.getSetting('SAM_Flag')))
                self.path_to_SAM_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samparse.exe")
                if not os.path.exists(self.path_to_SAM_file):
                   raise IngestModuleException("SAM Executable does not exist for Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "SAM ==> " + str(self.local_settings.getSetting('SAM_Flag')))
                self.path_to_SAM_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Samparse")
                if not os.path.exists(self.path_to_SAM_file):
                   raise IngestModuleException("SAM Executable does not exist for Linux")

        if self.local_settings.getSetting('Shellbags_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "shellbags ==> " + str(self.local_settings.getSetting('Shellbags_Flag')))
                self.path_to_Shellbags_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shellbags.exe")
                if not os.path.exists(self.path_to_Shellbags_file):
                   raise IngestModuleException("Shellbags Executable does not exist for Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "shellbags ==> " + str(self.local_settings.getSetting('Shellbags_Flag')))
                self.path_to_Shellbags_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shellbags")
                if not os.path.exists(self.path_to_Shellbags_file):
                   raise IngestModuleException("Shellbags Executable does not exist For Linux")

        if self.local_settings.getSetting('Shimcache_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "Shimcache ==> " + str(self.local_settings.getSetting('Shimcache_Flag')))
                self.path_to_Shimcache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shimcache_parser.exe")
                if not os.path.exists(self.path_to_Shimcache_file):
                   raise IngestModuleException("Shimcache Executable does not exist For Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "Shimcache ==> " + str(self.local_settings.getSetting('Shimcache_Flag')))
                self.path_to_Shimcache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Shimcache_parser")
                if not os.path.exists(self.path_to_Shimcache_file):
                   raise IngestModuleException("Shimcache Executable does not exist for Linux")

        if self.local_settings.getSetting('Usnj_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "USN ==> " + str(self.local_settings.getSetting('Usnj_Flag')))
                self.path_to_Usnj_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parseusn.exe")
                if not os.path.exists(self.path_to_Usnj_file):
                   raise IngestModuleException("Usnj Executable does not exist for Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "USN ==> " + str(self.local_settings.getSetting('Usnj_Flag')))
                self.path_to_Usnj_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parseusn")
                if not os.path.exists(self.path_to_Usnj_file):
                   raise IngestModuleException("Usnj Executable does not exist for linux")

        if self.local_settings.getSetting('Webcache_Flag') == 'true':
            if PlatformUtil.isWindowsOS():
                self.log(Level.INFO, "Webcache ==> " + str(self.local_settings.getSetting('Webcache_Flag')))
                self.path_to_Webcache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Export_Webcache.exe")
                if not os.path.exists(self.path_to_Webcache_file):
                   raise IngestModuleException("Webcache Executable does not exist for Windows")
            elif PlatformUtil.getOSName() == 'Linux':
                self.log(Level.INFO, "Webcache ==> " + str(self.local_settings.getSetting('Webcache_Flag')))
                self.path_to_Webcache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Export_Webcache")
                if not os.path.exists(self.path_to_Webcache_file):
                   raise IngestModuleException("Webcache Executable does not exist for Linux")

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
        
        if self.local_settings.getSetting('Recentlyused_Flag') == 'true':
            progressBar.progress("Processing Recently Used Apps")	
            self.process_Recentlyused(dataSource, progressBar)
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " Recentlyused Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        if self.local_settings.getSetting('Filehistory_Flag') == 'true':
            progressBar.progress("Processing File History")	
            self.process_Filehistory(dataSource, progressBar)
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " File History Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        if self.local_settings.getSetting('Jumplist_Flag') == 'true':
            progressBar.progress("Processing Jumplists")	
            self.log(Level.INFO, "Starting to process Jumplist")
            self.process_Jumplist(dataSource, progressBar)
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " Jumplist Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        if self.local_settings.getSetting('Prefetch_Flag') == 'true':
            progressBar.progress("Processing Prefetch")	
            self.process_Prefetch(dataSource, progressBar)
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " Prefetch Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        if self.local_settings.getSetting('SAM_Flag') == 'true':
            progressBar.progress("Processing SAM")	
            self.process_SAM(dataSource, progressBar)
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " SAM Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        if self.local_settings.getSetting('Shellbags_Flag') == 'true':
            progressBar.progress("Processing Shellbags")	
            self.process_Shellbags(dataSource, progressBar)
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " Shellbags Have Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        if self.local_settings.getSetting('Shimcache_Flag') == 'true':
            progressBar.progress("Processing Shimcache")	
            self.process_Shimcache(dataSource, progressBar)
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " Shimcache Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        if self.local_settings.getSetting('Usnj_Flag') == 'true':
            progressBar.progress("Processing UsnJ")	
            self.process_Usnj(dataSource, progressBar)        
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " Usnj Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        if self.local_settings.getSetting('Webcache_Flag') == 'true':
            progressBar.progress("Processing Webcache")	
            self.process_Webcache(dataSource, progressBar)
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Windows_Internals", " Webcache Has Been Analyzed " )
            IngestServices.getInstance().postMessage(message)

        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Windows_Internals", " Windows_Internals Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                

    def process_Recentlyused(self, dataSource, progressBar):
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
 
        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%", "/Windows/System32/wbem/Repository/")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Recently_Used")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "Recently Used Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            if (file.getName() == '.' or file.getName() == '..'):
                self.log(Level.INFO, "Parent or Root Directory File not writing")
            else:
                # Save the DB locally in the temp folder. use file id as name to reduce collisions
                lclDbPath = os.path.join(Temp_Dir, file.getName())
                ContentUtils.writeToFile(file, File(lclDbPath))

        self.log(Level.INFO, "Running prog ==> " + self.path_to_Recentlyused_file + " win7 " + Temp_Dir + "\Recently_Used " + " " + \
                                     Temp_Dir + "\\recentlyUsedApps.db3")
        pipe = Popen([self.path_to_Recentlyused_file, "win7", Temp_Dir, os.path.join(Temp_Dir,"recentlyUsedApps.db3")], stdout=PIPE, stderr=PIPE)
        
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text) 

        lclDbPath = os.path.join(Temp_Dir, "recentlyUsedApps.db3")        
        if ("Exiting" in out_text):
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "CCM Recently Used Apps", " Error in CCM Recently Used Apps module " )
            IngestServices.getInstance().postMessage(message)
        else:
            # Add custom Artifact to blackboard
            try:
               self.log(Level.INFO, "Begin Create New Artifacts ==> TSK_CCM_RECENTLY_USED_APPS")
               artID_art = skCase.addArtifactType("TSK_CCM_RECENTLY_USED_APPS", "WMI Recently Used Apps")
            except:		
               self.log(Level.INFO, "Artifacts Creation Error, artifact TSK_CCM_RECENTLY_USED_APPS exists. ==> ")

            # Add Custom attributes to blackboard
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_EXPLORER_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Explorer File Name")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Explorer File Name ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_FILE_SIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Size")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, File Size ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_LAST_USED_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last Used Time")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Last Used Time ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_TIME_ZONE_OFFSET", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time Zone Offset")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Time Zone Offset ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_LAUNCH_COUNT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Launch Count")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Launch Count ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_ORIG_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Original File Name")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Original File Name ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_FILE_DESC", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Description")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, File Description ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_PROD_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product Name")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Product Name ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_PROD_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product Version")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Product Version ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_FILE_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Version")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, File Version ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_ADDITIONAL_PROD_CODES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Additional Product Codes")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Additional Product Codes ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_MSI_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MSI Version")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, MSI Version ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_MSI_DISPLAY_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MSI Display Name")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, MSI Display Name ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_PRODUCT_CODE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product Code")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Product Code ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_SOFTWARE_PROP_HASH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Software Property Hash")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Software Property Hash ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_PROD_LANG", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product Language")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Product Language ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_FILE_PROP_HASH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Property Hash")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, File Property Hash ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_MSI_PUBLISHER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MSI Publisher")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, MSI Publisher ==> ")

            for file in files:
               if (file.getName() == "OBJECTS.DATA"):

                    # Open the DB using JDBC
                    lclDbPath = os.path.join(Temp_Dir, "recentlyUsedApps.db3")
                    self.log(Level.INFO, "Path the recentlyUsedApps.db3 database file created ==> " + lclDbPath)
                    try: 
                       Class.forName("org.sqlite.JDBC").newInstance()
                       dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                    except SQLException as e:
                       self.log(Level.INFO, "Could not open database file (not SQLite) recentlyUsedApps.db3 (" + e.getMessage() + ")")
                       return IngestModule.ProcessResult.OK
                    
                    # Query the history_visits table in the database and get all columns. 
                    try:
                       stmt = dbConn.createStatement()
                       recently_used_sql = "select FolderPath 'TSK_PATH', ExplorerFileName 'TSK_EXPLORER_FILE_NAME', " + \
                                           "FileSize 'TSK_FILE_SIZE', LastUserName 'TSK_USER_ID', strftime('%s',LastUsedTime) " + \
                                           "'TSK_LAST_USED_TIME', TimeZoneOffset 'TSK_TIME_ZONE_OFFSET', LaunchCount " + \
                                           "'TSK_LAUNCH_COUNT', OriginalFileName 'TSK_ORIG_FILE_NAME', FileDescription " + \
                                           "'TSK_FILE_DESC', CompanyName 'TSK_ORGANIZATION', ProductName 'TSK_PROD_NAME', " + \
                                           "ProductVersion 'TSK_PROD_VERSION', FileVersion 'TSK_FILE_VERSION', " + \
                                           "AdditionalProductCodes 'TSK_ADDITIONAL_PROD_CODES', msiVersion " + \
                                           "'TSK_MSI_VERSION', msiDisplayName 'TSK_MSI_DISPLAY_NAME', " + \
                                           "ProductCode 'TSK_PRODUCT_CODE', SoftwarePropertiesHash " + \
                                           "'TSK_SOFTWARE_PROP_HASH', ProductLanguage 'TSK_PROD_LANG', " + \
                                           "FilePropertiesHash 'TSK_FILE_PROP_HASH', msiPublisher 'TSK_MSI_PUBLISHER' " + \
                                           "from recently_used;"
                       self.log(Level.INFO, recently_used_sql)
                       resultSet = stmt.executeQuery(recently_used_sql)
                       self.log(Level.INFO, "query recently_used table")
                    except SQLException as e:
                       self.log(Level.INFO, "Error querying database for recently_used table (" + e.getMessage() + ")")
                       return IngestModule.ProcessResult.OK

                    artID_hst = skCase.getArtifactTypeID("TSK_CCM_RECENTLY_USED_APPS")
                    artID_hst_evt = skCase.getArtifactType("TSK_CCM_RECENTLY_USED_APPS")

                    meta = resultSet.getMetaData()
                    columncount = meta.getColumnCount()
                    column_names = []
                    self.log(Level.INFO, "Number of Columns in the table ==> " + str(columncount))
                    for x in range (1, columncount + 1):
                        self.log(Level.INFO, "Column Name ==> " + meta.getColumnLabel(x))
                        column_names.append(meta.getColumnLabel(x))
                    
                    self.log(Level.INFO, "All Columns ==> " + str(column_names))
                    # Cycle through each row and create artifacts
                    while resultSet.next():
                       try: 
                           #self.log(Level.INFO, SQL_String_1)
                           self.log(Level.INFO, "Artifact Is ==> " + str(artID_hst))
                           
                           art = file.newArtifact(artID_hst)
                           self.log(Level.INFO, "Inserting attribute URL")
                           for col_name in column_names:
                               attID_ex1 = skCase.getAttributeType(col_name)
                               self.log(Level.INFO, "Inserting attribute ==> " + str(attID_ex1))
                               self.log(Level.INFO, "Attribute Type ==> " + str(attID_ex1.getValueType()))
                               if attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet.getString(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes String Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Integer Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Long Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Double Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet.getString(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Byte Creation Error, " + col_name + " ==> ")
                               else:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, int(resultSet.getString(col_name))))
                                    except:		
                                        self.log(Level.INFO, "Attributes Datatime Creation Error, " + col_name + " ==> ")

                           # index the artifact for keyword search
                           try:
                               blackboard.indexArtifact(art)
                           except:
                               self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
                       except SQLException as e:
                           self.log(Level.INFO, "Error getting values from web_history table (" + e.getMessage() + ")")

                    IngestServices.getInstance().fireModuleDataEvent(
                           ModuleDataEvent(Windows_InternalsIngestModuleFactory.moduleName, artID_hst_evt, None))

                    stmt.close()
                    dbConn.close()

        # Clean up
        try:
           os.remove(lclDbPath)
        except:
		   self.log(Level.INFO, "removal of Recently Used database failed ")
		#Clean up EventLog directory and files
        for file in files:
           try:
              os.remove(os.path.join(Temp_Dir), file.getName())
           except:
              self.log(Level.INFO, "removal of Recently Used files failed " + os.path.join(Temp_Dir, file.getName()))
        try:
           shutil.rmtree(Temp_Dir)		
        except:
		   self.log(Level.INFO, "removal of recently used directory failed " + Temp_Dir)

    def process_Filehistory(self, dataSource, progressBar):

 
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Check to see if the artifacts exist and if not then create it, also check to see if the attributes
		# exist and if not then create them
        skCase = Case.getCurrentCase().getSleuthkitCase();
                
        # This will work in 4.0.1 and beyond
        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_cat1 = skCase.addArtifactType( "TSK_FH_CATALOG_1", "File History Catalog 1")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, Catalog 1. ==> ")
             artID_cat1 = skCase.getArtifactTypeID("TSK_FH_CATALOG_1")
        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_cat2 = skCase.addArtifactType( "TSK_FH_CATALOG_2", "File History Catalog 2")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, Catalog 2. ==> ")
             artID_cat2 = skCase.getArtifactTypeID("TSK_FH_CATALOG_2")
             
        # Create the attribute type, if it exists then catch the error
        try:
            attID_fh_pn = skCase.addArtifactAttributeType('TSK_FH_PATH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Path")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Prefetch Parent Path. ==> ")

        try:
            attID_fh_fn = skCase.addArtifactAttributeType('TSK_FH_FILE_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Name")			 
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Name. ==> ")

        try:
            attID_fh_fs = skCase.addArtifactAttributeType('TSK_FH_FILE_SIZE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Size")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Size. ==> ")

        try:
            attID_fh_usn = skCase.addArtifactAttributeType('TSK_FH_USN_JOURNAL_ENTRY', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "USN Journal Entry")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, USN Journal Entry. ==> ")

        try:
            attID_fh_fc = skCase.addArtifactAttributeType('TSK_FH_FILE_CREATED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "File Created")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Created. ==> ")

        try:
            attID_fh_fm = skCase.addArtifactAttributeType('TSK_FH_FILE_MODIFIED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "File Modified")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 3. ==> ")

        try:
            attID_fh_bq = skCase.addArtifactAttributeType('TSK_FH_BACKUP_QUEUED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Queued")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Queued ==> ")

        try:
            attID_fh_bc = skCase.addArtifactAttributeType('TSK_FH_BACKUP_CREATED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Created")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Created ==> ")

        try:
            attID_fh_bcp = skCase.addArtifactAttributeType('TSK_FH_BACKUP_CAPTURED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Captured")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Captured. ==> ")

        try:
            attID_fh_bu = skCase.addArtifactAttributeType('TSK_FH_BACKUP_UPDATED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Updated")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Updated. ==> ")

        try:
            attID_fh_bv = skCase.addArtifactAttributeType('TSK_FH_BACKUP_VISIBLE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Visible")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Visible ==> ")

        self.log(Level.INFO, "Get Artifacts after they were created.")
        # Get the new artifacts and attributes that were just created
        #artID_wfh = skCase.getArtifactTypeID("TSK_PREFETCH")
        #artID_cat1 = skCase.getArtifactType("TSK_FH_CATALOG_1")
        #artID_cat2 = skCase.getArtifactType("TSK_FH_CATALOG_2")
        attID_fh_pn = skCase.getAttributeType("TSK_FH_PATH")
        attID_fh_fn = skCase.getAttributeType("TSK_FH_FILE_NAME")
        attID_fh_fs = skCase.getAttributeType("TSK_FH_FILE_SIZE")
        attID_fh_usn = skCase.getAttributeType("TSK_FH_USN_JOURNAL_ENTRY")
        attID_fh_fc = skCase.getAttributeType("TSK_FH_FILE_CREATED")
        attID_fh_fm = skCase.getAttributeType("TSK_FH_FILE_MODIFIED")
        attID_fh_bq = skCase.getAttributeType("TSK_FH_BACKUP_QUEUED")
        attID_fh_bc = skCase.getAttributeType("TSK_FH_BACKUP_CREATED")
        attID_fh_bcp = skCase.getAttributeType("TSK_FH_BACKUP_CAPTURED")
        attID_fh_bu = skCase.getAttributeType("TSK_FH_BACKUP_UPDATED")
        attID_fh_bv = skCase.getAttributeType("TSK_FH_BACKUP_VISIBLE")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Find the file history files from the users folders
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%edb", "%/Windows/FileHistory/%")
        
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
		
        # Create file history directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "File_History")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "File_History Directory already exists " + Temp_Dir)
			
        # Write out each catalog esedb database to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir, file.getName() + "_" + str(file.getId()))
            db_name = os.path.splitext(file.getName())[0]
            lclSQLPath = os.path.join(Temp_Dir, db_name + "_" + str(file.getId()) + ".db3")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Run the EXE, saving output to a sqlite database
            self.log(Level.INFO, "Running program on data source parm 1 ==> " + self.path_to_Filehistory_file + " " + lclDbPath + " " + lclSQLPath)
            pipe = Popen([self.path_to_Filehistory_file, lclDbPath, lclSQLPath], stdout=PIPE, stderr=PIPE)
            
            out_text = pipe.communicate()[0]
            self.log(Level.INFO, "Output from run is ==> " + out_text)                
		
            if db_name == "Catalog1":
                artID_fh = skCase.getArtifactTypeID("TSK_FH_CATALOG_1")
                artID_fh_evt = skCase.getArtifactType("TSK_FH_CATALOG_1")
            else:
                artID_fh = skCase.getArtifactTypeID("TSK_FH_CATALOG_2")
                artID_fh_evt = skCase.getArtifactType("TSK_FH_CATALOG_2")

            userpath = file.getParentPath()
            username = userpath.split('/')
            self.log(Level.INFO, "Getting Username " + username[2]   )
        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclSQLPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + lclSQLPath + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
                
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = "Select ParentName 'TSK_FH_PATH', Childname 'TSK_FH_FILE_NAME', " + \
                                  "Filesize 'TSK_FH_FILE_SIZE', " + \
                                  "usn 'TSK_FH_USN_JOURNAL_ENTRY', " + \
                                  "FileCreated 'TSK_FH_FILE_CREATED', filemodified 'TSK_FH_FILE_MODIFIED', " + \
                                  "tqueued 'TSK_FH_BACKUP_QUEUED', tcreated 'TSK_FH_BACKUP_CREATED', " + \
                                  "tcaptured 'TSK_FH_BACKUP_CAPTURED', tupdated 'TSK_FH_BACKUP_UPDATED', " + \
                                  "tvisible 'TSK_FH_BACKUP_VISIBLE' from file_history"
                self.log(Level.INFO, "SQL Statement --> " + SQL_Statement)
                resultSet = stmt.executeQuery(SQL_Statement)
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for File_History table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    #self.log(Level.INFO, "Result (" + resultSet.getString("Prefetch_File_Name") + ")")
                    FH_Path  = resultSet.getString("TSK_FH_PATH")
                    FH_File_Name = resultSet.getString("TSK_FH_FILE_NAME")
                    FH_Filesize = resultSet.getString("TSK_FH_FILE_SIZE")
                    FH_Usn = resultSet.getString("TSK_FH_USN_JOURNAL_ENTRY")
                    FH_FC = resultSet.getInt("TSK_FH_FILE_CREATED")
                    FH_FM = resultSet.getInt("TSK_FH_FILE_MODIFIED")
                    FH_BQ = resultSet.getInt("TSK_FH_BACKUP_QUEUED")
                    FH_BC = resultSet.getInt("TSK_FH_BACKUP_CREATED")
                    FH_BCP = resultSet.getInt("TSK_FH_BACKUP_CAPTURED")
                    FH_BU = resultSet.getInt("TSK_FH_BACKUP_UPDATED")
                    FH_BV = resultSet.getInt("TSK_FH_BACKUP_VISIBLE")
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

                # Make artifact for TSK_PREFETCH,  this can happen when custom attributes are fully supported
                art = file.newArtifact(artID_fh)
    

                # Add the attributes to the artifact.
                art.addAttributes(((BlackboardAttribute(attID_fh_pn, Windows_InternalsIngestModuleFactory.moduleName, FH_Path)), \
                                  (BlackboardAttribute(attID_fh_fn, Windows_InternalsIngestModuleFactory.moduleName, FH_File_Name)), \
                                  (BlackboardAttribute(attID_fh_fs, Windows_InternalsIngestModuleFactory.moduleName, FH_Filesize)), \
                                  (BlackboardAttribute(attID_fh_usn, Windows_InternalsIngestModuleFactory.moduleName, FH_Usn)), \
                                  (BlackboardAttribute(attID_fh_fc, Windows_InternalsIngestModuleFactory.moduleName, FH_FC)), \
                                  (BlackboardAttribute(attID_fh_fm, Windows_InternalsIngestModuleFactory.moduleName, FH_FM)), \
                                  (BlackboardAttribute(attID_fh_bq, Windows_InternalsIngestModuleFactory.moduleName, FH_BQ)), \
                                  (BlackboardAttribute(attID_fh_bc, Windows_InternalsIngestModuleFactory.moduleName, FH_BC)), \
                                  (BlackboardAttribute(attID_fh_bcp, Windows_InternalsIngestModuleFactory.moduleName, FH_BCP)), \
                                  (BlackboardAttribute(attID_fh_bu, Windows_InternalsIngestModuleFactory.moduleName, FH_BU)), \
                                  (BlackboardAttribute(attID_fh_bv, Windows_InternalsIngestModuleFactory.moduleName, FH_BV)), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), \
                                    Windows_InternalsIngestModuleFactory.moduleName, username[2]))))
                
                try:
                    #index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
            IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(Windows_InternalsIngestModuleFactory.moduleName, artID_fh_evt, None))
            
            # Clean up
            stmt.close()
            dbConn.close()
            #os.remove(lclDbPath)
			
		#Clean up prefetch directory and files
        try:
             shutil.rmtree(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + Temp_Dir)
            
    def process_Jumplist(self, dataSource, progressBar):
        
        self.path_to_app_id_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Jump_List_App_Ids.db3")
        
        #skCase Check to see if the artifacts exist and if not then create it, also check to see if the attributes
		# exist and if not then create them
        skCase = Case.getCurrentCase().getSleuthkitCase();
        #skCase_Tran = skCase.beginTransaction()

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_jl_ad = skCase.addArtifactType( "TSK_JL_AD", "Jump List Auto Dest")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_jl_ad = skCase.getArtifactTypeID("TSK_JL_AD")

        try:
            attID_jl_fn = skCase.addArtifactAttributeType("TSK_JLAD_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "JumpList File Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, JL AD File Name. ==> ")
        try:
            attID_jl_fg = skCase.addArtifactAttributeType("TSK_JLAD_FILE_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Description")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Description. ==> ")
        try:
            attID_jl_in = skCase.addArtifactAttributeType("TSK_JLAD_ITEM_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Item Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Item Name. ==> ")
        try:
            attID_jl_cl = skCase.addArtifactAttributeType("TSK_JLAD_COMMAND_LINE_ARGS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Command Line Args")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Command Line Arguments. ==> ")
        try:
            attID_jl_dt = skCase.addArtifactAttributeType("TSK_JLAD_Drive Type", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Drive Type")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Drive Type. ==> ")
        try:
            attID_jl_dsn = skCase.addArtifactAttributeType("TSK_JLAD_DRIVE_SERIAL_NUMBER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Drive Serial Number")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Drive Serial Number. ==> ")
        try:
            attID_jl_des = skCase.addArtifactAttributeType("TSK_JLAD_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Description")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Description. ==> ")
        try:
            attID_jl_evl = skCase.addArtifactAttributeType("TSK_JLAD_ENVIRONMENT_VARIABLES_LOCATION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Env Var Location")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Env Var Location. ==> ")
        try:
            attID_jl_fat = skCase.addArtifactAttributeType("TSK_JLAD_FILE_ACCESS_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Access Time")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Access Time. ==> ")
        try:
            attID_jl_faf = skCase.addArtifactAttributeType("TSK_JLAD_FILE_ATTRIBUTE_FLAGS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "File Attribute Flags")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Attribute Flags. ==> ")
        try:
            attID_jl_fct = skCase.addArtifactAttributeType("TSK_JLAD_FILE_CREATION_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Creation Time")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Creation Time. ==> ")
        try:
            attID_jl_fmt = skCase.addArtifactAttributeType("TSK_JLAD_FILE_MODIFICATION_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Modification Time")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Modification Time. ==> ")
        try:
            attID_jl_fs = skCase.addArtifactAttributeType("TSK_JLAD_FILE_SIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "File Size")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Size. ==> ")
        try:
            attID_jl_ic = skCase.addArtifactAttributeType("TSK_JLAD_ICON_LOCATION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Icon Location")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Icon Location. ==> ")
        try:
            attID_jl_ltid = skCase.addArtifactAttributeType("TSK_JLAD_LINK_TARGET_IDENTIFIER_DATA", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Link Target Identifier Data")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Link Target Identifier Data. ==> ")
        try:
            attID_jl_lp = skCase.addArtifactAttributeType("TSK_JLAD_LOCAL_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Local Path")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Modification Time. ==> ")
        try:
            attID_jl_mi = skCase.addArtifactAttributeType("TSK_JLAD_FILE_MACHINE_IDENTIFIER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Machine Identifier")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Machine Identifier. ==> ")
        try:
            attID_jl_np = skCase.addArtifactAttributeType("TSK_JLAD_NETWORK_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Network Path")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Network Path. ==> ")
        try:
            attID_jl_rp = skCase.addArtifactAttributeType("TSK_JLAD_RELATIVE_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Relative Path")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Relative Path. ==> ")
        try:
            attID_jl_vl = skCase.addArtifactAttributeType("TSK_JLAD_VOLUME_LABEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Volume Label")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Volume Label. ==> ")
        try:
            attID_jl_wc = skCase.addArtifactAttributeType("TSK_JLAD_WORKING_DIRECTORY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Working Directory")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Working Directory. ==> ")

        # Get the new artifacts and attributes that were just created
        artID_jl_ad = skCase.getArtifactTypeID("TSK_JL_AD")
        artID_jl_ad_evt = skCase.getArtifactType("TSK_JL_AD")
        attID_jl_fn = skCase.getAttributeType("TSK_JLAD_FILE_NAME")
        attID_jl_fg = skCase.getAttributeType("TSK_JLAD_FILE_DESCRIPTION")
        attID_jl_in = skCase.getAttributeType("TSK_JLAD_ITEM_NAME")			 
        attID_jl_cl = skCase.getAttributeType("TSK_JLAD_COMMAND_LINE_ARGS")
        attID_jl_dt = skCase.getAttributeType("TSK_JLAD_Drive Type")
        attID_jl_dsn = skCase.getAttributeType("TSK_JLAD_DRIVE_SERIAL_NUMBER")
        attID_jl_des = skCase.getAttributeType("TSK_JLAD_DESCRIPTION")
        attID_jl_evl = skCase.getAttributeType("TSK_JLAD_ENVIRONMENT_VARIABLES_LOCATION")
        attID_jl_fat = skCase.getAttributeType("TSK_JLAD_FILE_ACCESS_TIME")
        attID_jl_faf = skCase.getAttributeType("TSK_JLAD_FILE_ATTRIBUTE_FLAGS")
        attID_jl_fct = skCase.getAttributeType("TSK_JLAD_FILE_CREATION_TIME")
        attID_jl_fmt = skCase.getAttributeType("TSK_JLAD_FILE_MODIFICATION_TIME")
        attID_jl_fs = skCase.getAttributeType("TSK_JLAD_FILE_SIZE")
        attID_jl_ic = skCase.getAttributeType("TSK_JLAD_ICON_LOCATION")
        attID_jl_ltid = skCase.getAttributeType("TSK_JLAD_LINK_TARGET_IDENTIFIER_DATA")
        attID_jl_lp = skCase.getAttributeType("TSK_JLAD_LOCAL_PATH")
        attID_jl_mi = skCase.getAttributeType("TSK_JLAD_FILE_MACHINE_IDENTIFIER")
        attID_jl_np = skCase.getAttributeType("TSK_JLAD_NETWORK_PATH")
        attID_jl_rp = skCase.getAttributeType("TSK_JLAD_RELATIVE_PATH")
        attID_jl_vl = skCase.getAttributeType("TSK_JLAD_VOLUME_LABEL")
        attID_jl_wd = skCase.getAttributeType("TSK_JLAD_WORKING_DIRECTORY")
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Find the Windows Event Log Files
        files = []		
        
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.automaticDestinations-ms")

        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
		
        # Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "JL_SD")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "JL_AD Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir, file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on data source parm 1 ==> " + Temp_Dir + "  Parm 2 ==> " + os.path.join(Temp_Dir, "JL_AD.db3"))
        pipe = Popen([self.path_to_Jumplist_file, Temp_Dir, os.path.join(Temp_Dir, "JL_AD.db3"), self.path_to_app_id_db], stdout=PIPE, stderr=PIPE)
        
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text)                
        
        # Set the database to be read to the one created by the Event_EVTX program
        lclDbPath = os.path.join(Temp_Dir, "JL_AD.db3")
        self.log(Level.INFO, "Path to the JL_AD database file created ==> " + lclDbPath)
                        
        # Open the DB using JDBC
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
            
#        fileManager = Case.getCurrentCase().getServices().getFileManager()
#        files = fileManager.findFiles(dataSource, "%.automaticDestinations-ms")
            
        for file in files:
            file_name = os.path.splitext(file.getName())[0]
            self.log(Level.INFO, "File To process in SQL " + file_name + "  <<=====")
            # Query the table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = "select File_Name, File_Description, Item_Name, command_line_arguments, drive_type, drive_serial_number, " + \
                                " description, environment_variables_location, file_access_time, file_attribute_flags, file_creation_time, " + \
                                " file_modification_time, file_size, icon_location, link_target_identifier_data, local_path, " + \
                                " machine_identifier, network_path, relative_path, volume_label, working_directory " + \
                                " from Automatic_destinations_JL where upper(File_Name) = upper('" + file_name + "');"
            	resultSet = stmt.executeQuery(SQL_Statement)
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                
                    File_Name = resultSet.getString("File_Name")
                    File_Description = resultSet.getString("File_Description")
                    Item_Name = resultSet.getString("Item_Name")
                    Command_Line_Arguments = resultSet.getString("command_line_arguments")
                    Drive_Type = resultSet.getInt("drive_type")
                    Drive_Serial_Number = resultSet.getInt("drive_serial_number")
                    Description = resultSet.getString("description")
                    Environment_Variables_Location = resultSet.getString("environment_variables_location")
                    File_Access_Time = resultSet.getString("file_access_time")
                    File_Attribute_Flags = resultSet.getInt("file_attribute_flags")
                    File_Creation_Time = resultSet.getString("file_creation_time")
                    File_Modification_Time = resultSet.getString("file_modification_time")
                    File_Size = resultSet.getInt("file_size")
                    Icon_Location = resultSet.getString("icon_location")
                    Link_Target_Identifier_Data = resultSet.getString("link_target_identifier_data")
                    Local_Path = resultSet.getString("local_path")
                    Machine_Identifier = resultSet.getString("machine_identifier")
                    Network_Path = resultSet.getString("network_path")
                    Relative_Path = resultSet.getString("relative_path")
                    Volume_Label = resultSet.getString("volume_label")
                    Working_Directory = resultSet.getString("working_directory")                
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
        
                art = file.newArtifact(artID_jl_ad)

                # Add attributes
                art.addAttributes(((BlackboardAttribute(attID_jl_fn, Windows_InternalsIngestModuleFactory.moduleName, File_Name)), \
                                   (BlackboardAttribute(attID_jl_fg, Windows_InternalsIngestModuleFactory.moduleName, File_Description)), \
                                   (BlackboardAttribute(attID_jl_in, Windows_InternalsIngestModuleFactory.moduleName, Item_Name)), \
                                   (BlackboardAttribute(attID_jl_cl, Windows_InternalsIngestModuleFactory.moduleName, Command_Line_Arguments)), \
                                   (BlackboardAttribute(attID_jl_dt, Windows_InternalsIngestModuleFactory.moduleName, Drive_Type)), \
                                   (BlackboardAttribute(attID_jl_dsn, Windows_InternalsIngestModuleFactory.moduleName, Drive_Serial_Number)), \
                                   (BlackboardAttribute(attID_jl_des, Windows_InternalsIngestModuleFactory.moduleName, Description)), \
                                   (BlackboardAttribute(attID_jl_evl, Windows_InternalsIngestModuleFactory.moduleName, Environment_Variables_Location)), \
                                   (BlackboardAttribute(attID_jl_fat, Windows_InternalsIngestModuleFactory.moduleName, File_Access_Time)), \
                                   (BlackboardAttribute(attID_jl_faf, Windows_InternalsIngestModuleFactory.moduleName, File_Attribute_Flags)), \
                                   (BlackboardAttribute(attID_jl_fct, Windows_InternalsIngestModuleFactory.moduleName, File_Creation_Time)), \
                                   (BlackboardAttribute(attID_jl_fmt, Windows_InternalsIngestModuleFactory.moduleName, File_Modification_Time)), \
                                   (BlackboardAttribute(attID_jl_fs, Windows_InternalsIngestModuleFactory.moduleName, File_Size)), \
                                   (BlackboardAttribute(attID_jl_ic, Windows_InternalsIngestModuleFactory.moduleName, Icon_Location)), \
                                   (BlackboardAttribute(attID_jl_ltid, Windows_InternalsIngestModuleFactory.moduleName, Link_Target_Identifier_Data)), \
                                   (BlackboardAttribute(attID_jl_lp, Windows_InternalsIngestModuleFactory.moduleName, Local_Path)), \
                                   (BlackboardAttribute(attID_jl_mi, Windows_InternalsIngestModuleFactory.moduleName, Machine_Identifier)), \
                                   (BlackboardAttribute(attID_jl_np, Windows_InternalsIngestModuleFactory.moduleName, Network_Path)), \
                                   (BlackboardAttribute(attID_jl_rp, Windows_InternalsIngestModuleFactory.moduleName, Relative_Path)), \
                                   (BlackboardAttribute(attID_jl_vl, Windows_InternalsIngestModuleFactory.moduleName, Volume_Label)), \
                                   (BlackboardAttribute(attID_jl_wd, Windows_InternalsIngestModuleFactory.moduleName, Working_Directory))))
			
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
            # Fire an event to notify the UI and others that there are new artifacts  
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(Windows_InternalsIngestModuleFactory.moduleName, artID_jl_ad_evt, None))
                
            # Clean up
            #skCase_Tran.commit()
            stmt.close()
        
        dbConn.close()
        os.remove(lclDbPath)
        			
		#Clean up EventLog directory and files
        # for file in files:
            # try:
			    # os.remove(Temp_Dir + "\\JL_AD\\" + file.getName())
            # except:
			    # self.log(Level.INFO, "removal of JL_AD file failed " + Temp_Dir + "\\" + file.getName())
        try:
             shutil.rmtree(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of JL_AD directory failed " + Temp_Dir)
    
    def process_Prefetch(self, dataSource, progressBar):
        # Check to see if the artifacts exist and if not then create it, also check to see if the attributes
		# exist and if not then create them
        skCase = Case.getCurrentCase().getSleuthkitCase();
                
        # This will work in 4.0.1 and beyond
        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_pf = skCase.addArtifactType( "TSK_PREFETCH", "Windows Prefetch")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_pf = skCase.getArtifactTypeID("TSK_PREFETCH")
             
        # Create the attribute type, if it exists then catch the error
        try:
            attID_pf_fn = skCase.addArtifactAttributeType("TSK_PREFETCH_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Prefetch File Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Prefetch File Name. ==> ")

        try:
            attID_pf_an = skCase.addArtifactAttributeType("TSK_PREFETCH_ACTUAL_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Actual File Name")			 
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Actual File Name. ==> ")

        try:
            attID_nr = skCase.addArtifactAttributeType("TSK_PF_RUN_COUNT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Program Number Runs")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Program Number Runs. ==> ")

        try:
            attID_ex1 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_1", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 1")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 1. ==> ")

        try:
            attID_ex2 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_2", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 2")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 2. ==> ")

        try:
            attID_ex3 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_3", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 3")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 3. ==> ")

        try:
            attID_ex4 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_4", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 4")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 4 ==> ")

        try:
            attID_ex5 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_5", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 5")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 5. ==> ")

        try:
            attID_ex6 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_6", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 6")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 6. ==> ")

        try:
            attID_ex7 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_7", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 7")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 7. ==> ")

        try:
            attID_ex8 = skCase.addArtifactAttributeType("TSK_PF_EXEC_DTTM_8", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "PF Execution DTTM 8")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 8 ==> ")

        self.log(Level.INFO, "Get Artifacts after they were created.")
        # Get the new artifacts and attributes that were just created
        artID_pf = skCase.getArtifactTypeID("TSK_PREFETCH")
        artID_pf_evt = skCase.getArtifactType("TSK_PREFETCH")
        attID_pf_fn = skCase.getAttributeType("TSK_PREFETCH_FILE_NAME")
        attID_pf_an = skCase.getAttributeType("TSK_PREFETCH_ACTUAL_FILE_NAME")
        attID_nr = skCase.getAttributeType("TSK_PF_RUN_COUNT")
        attID_ex1 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_1")
        attID_ex2 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_2")
        attID_ex3 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_3")
        attID_ex4 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_4")
        attID_ex5 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_5")
        attID_ex6 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_6")
        attID_ex7 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_7")
        attID_ex8 = skCase.getAttributeType("TSK_PF_EXEC_DTTM_8")

        # Used to crossref ADS prefetch files
        prefetchFileName = {}

        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Find the prefetch files and the layout.ini file from the /windows/prefetch folder
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.pf")
        
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
		
        # Create prefetch directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Prefetch_Files")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "Prefetch Directory already exists " + Temp_Dir)
			
        # Write out each prefetch file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            fileName = file.getName()
            if (":" in fileName):
                fileName = fileName.replace(":", "-")
                prefetchFileName[fileName] = file
            else:
                prefetchFileName[fileName] = file
            lclDbPath = os.path.join(Temp_Dir, file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on data source parm 1 ==> " + Temp_Dir + "  Parm 2 ==> " + Case.getCurrentCase().getTempDirectory())
        pipe = Popen([self.path_to_Prefetch_file, Temp_Dir, os.path.join(Temp_Dir, "Autopsy_PF_DB.db3")], stdout=PIPE, stderr=PIPE)
        
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text)                
			
        # Set the database to be read to the once created by the prefetch parser program
        lclDbPath = os.path.join(Temp_Dir, "Autopsy_PF_DB.db3")
        self.log(Level.INFO, "Path the prefetch database file created ==> " + lclDbPath)
                        
        # Open the DB using JDBC
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
            
        # Query the contacts table in the database and get all columns. 
        try:
            stmt = dbConn.createStatement()
            resultSet = stmt.executeQuery("Select prefetch_File_Name, actual_File_Name, Number_time_file_run, " +
                                          " Embeded_date_Time_Unix_1, " +
                                          " Embeded_date_Time_Unix_2, " +
                                          " Embeded_date_Time_Unix_3, " +
                                          " Embeded_date_Time_Unix_4, " +
                                          " Embeded_date_Time_Unix_5, " +
                                          " Embeded_date_Time_Unix_6, " +   
                                          " Embeded_date_Time_Unix_7, " +       
                                          " Embeded_date_Time_Unix_8 " +
                                          " from prefetch_file_info ")
        except SQLException as e:
            self.log(Level.INFO, "Error querying database for Prefetch table (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK

        # Cycle through each row and create artifacts
        while resultSet.next():
            try: 
                self.log(Level.INFO, "Result (" + resultSet.getString("Prefetch_File_Name") + ")")
                Prefetch_File_Name  = resultSet.getString("Prefetch_File_Name")
                Actual_File_Name = resultSet.getString("Actual_File_Name")
                Number_Of_Runs = resultSet.getString("Number_Time_File_Run")
                Time_1 = resultSet.getInt("Embeded_date_Time_Unix_1")
                Time_2 = resultSet.getInt("Embeded_date_Time_Unix_2")
                Time_3 = resultSet.getInt("Embeded_date_Time_Unix_3")
                Time_4 = resultSet.getInt("Embeded_date_Time_Unix_4")
                Time_5 = resultSet.getInt("Embeded_date_Time_Unix_5")
                Time_6 = resultSet.getInt("Embeded_date_Time_Unix_6")
                Time_7 = resultSet.getInt("Embeded_date_Time_Unix_7")
                Time_8 = resultSet.getInt("Embeded_date_Time_Unix_8")
            except SQLException as e:
                self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

            file = prefetchFileName[Prefetch_File_Name]
            # Make artifact for TSK_PREFETCH,  this can happen when custom attributes are fully supported
            art = file.newArtifact(artID_pf)

            # Add the attributes to the artifact.
            art.addAttributes(((BlackboardAttribute(attID_pf_fn, Windows_InternalsIngestModuleFactory.moduleName, file.getName())), \
                              (BlackboardAttribute(attID_pf_an, Windows_InternalsIngestModuleFactory.moduleName, Actual_File_Name)), \
                              (BlackboardAttribute(attID_nr, Windows_InternalsIngestModuleFactory.moduleName, Number_Of_Runs)), \
                              (BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, Time_1)), \
                              (BlackboardAttribute(attID_ex2, Windows_InternalsIngestModuleFactory.moduleName, Time_2)), \
                              (BlackboardAttribute(attID_ex3, Windows_InternalsIngestModuleFactory.moduleName, Time_3)), \
                              (BlackboardAttribute(attID_ex4, Windows_InternalsIngestModuleFactory.moduleName, Time_4)), \
                              (BlackboardAttribute(attID_ex5, Windows_InternalsIngestModuleFactory.moduleName, Time_5)), \
                              (BlackboardAttribute(attID_ex6, Windows_InternalsIngestModuleFactory.moduleName, Time_6)), \
                              (BlackboardAttribute(attID_ex7, Windows_InternalsIngestModuleFactory.moduleName, Time_7)), \
                              (BlackboardAttribute(attID_ex8, Windows_InternalsIngestModuleFactory.moduleName, Time_8))))
            
            try:
                #index the artifact for keyword search
                blackboard.indexArtifact(art)
            except:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
			
        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(Windows_InternalsIngestModuleFactory.moduleName, artID_pf_evt, None))
        # Clean up
        try:
            stmt.close()
            dbConn.close()
            os.remove(lclDbPath)
        except:
            self.log(Level.INFO, "could not remove the prefetch database " + lclDbPath)
			
		#Clean up prefetch directory and files
        try:
             shutil.rmtree(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + Temp_Dir)
            
    def process_SAM(self, dataSource, progressBar):
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Set the database to be read to the once created by the SAM parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        
        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "SAM", "config")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "SAM")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "SAM Directory already exists " + Temp_Dir)
			
        # Write out each SAM file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir, file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on data source parm 1 ==> " + Temp_Dir + "  Parm 2 ==> " + Temp_Dir + "\\SAM.db3")
        pipe = Popen([self.path_to_SAM_file, os.path.join(Temp_Dir, "SAM"), os.path.join(Temp_Dir, "SAM.db3")], stdout=PIPE, stderr=PIPE)
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text)               
               
        for file in files:	
           # Open the DB using JDBC
           lclDbPath = os.path.join(Temp_Dir, "SAM.db3")
           self.log(Level.INFO, "Path the SAM database file created ==> " + lclDbPath)
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
            
           # Query the contacts table in the database and get all columns. 
           try:
               stmt = dbConn.createStatement()
               resultSet = stmt.executeQuery("Select tbl_name from SQLITE_MASTER; ")
               self.log(Level.INFO, "query SQLite Master table")
           except SQLException as e:
               self.log(Level.INFO, "Error querying database for SAM table (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK

           try:
                self.log(Level.INFO, "Begin Create New Artifacts")
                artID_sam = skCase.addArtifactType( "TSK_SAM", "SAM File")
           except:		
                self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

           artID_sam = skCase.getArtifactTypeID("TSK_SAM")
           artID_sam_evt = skCase.getArtifactType("TSK_SAM")
             
           # Cycle through each row and create artifacts
           while resultSet.next():
               try: 
                   self.log(Level.INFO, "Result (" + resultSet.getString("tbl_name") + ")")
                   table_name = resultSet.getString("tbl_name")
                   SQL_String_1 = "Select * from " + table_name + ";"
                   SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
				   
                   Column_Names = []
                   Column_Types = []
                   resultSet2  = stmt.executeQuery(SQL_String_2)
                   while resultSet2.next(): 
                      Column_Names.append(resultSet2.getString("name").upper())
                      Column_Types.append(resultSet2.getString("type"))
                      if resultSet2.getString("type") == "text":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      else:
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
										 
                   resultSet3 = stmt.executeQuery(SQL_String_1)
                   while resultSet3.next():
                      art = file.newArtifact(artID_sam)
                      Column_Number = 1
                      for col_name in Column_Names:
                         c_name = "TSK_" + col_name
                         attID_ex1 = skCase.getAttributeType(c_name)
                         if Column_Types[Column_Number - 1] == "text":
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                         else:
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getInt(Column_Number)))
                         Column_Number = Column_Number + 1

                      # index the artifact for keyword search
                      try:
                          blackboard.indexArtifact(art)
                      except:
                          self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                         
               except SQLException as e:
                   self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

        # Clean up
           stmt.close()
           dbConn.close()
           os.remove(lclDbPath)
			
		#Clean up EventLog directory and files
        try:
             shutil.rmtree(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + Temp_Dir)

    def process_Shimcache(self, dataSource, progressBar):
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Set the database to be read to the once created by the SAM parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
 
        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "SYSTEM", "config")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Shimcache")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "Shimcache Directory already exists " + Temp_Dir)
			
        for file in files:	
           # Check if the user pressed cancel while we were busy
           if self.context.isJobCancelled():
               return IngestModule.ProcessResult.OK

           #self.log(Level.INFO, "Processing file: " + file.getName())
           fileCount += 1

           # Save the DB locally in the temp folder. use file id as name to reduce collisions
           lclDbPath = os.path.join(Temp_Dir, file.getName())
           ContentUtils.writeToFile(file, File(lclDbPath))
           self.log(Level.INFO, "Saved File ==> " + lclDbPath)

           # Run the EXE, saving output to a sqlite database
           self.log(Level.INFO, "Running program ==> " + self.path_to_Shimcache_file + " " + os.path.join(Temp_Dir, file.getName() + " " + os.path.join(Temp_Dir, "Shimcache_db.db3")))
           pipe = Popen([self.path_to_Shimcache_file, os.path.join(Temp_Dir, file.getName()), os.path.join(Temp_Dir, "Shimcache_db.db3")], stdout=PIPE, stderr=PIPE)
           out_text = pipe.communicate()[0]
           self.log(Level.INFO, "Output from run is ==> " + out_text)               
               
           # Open the DB using JDBC
           lclDbPath = os.path.join(Temp_Dir, "Shimcache_db.db3")
           self.log(Level.INFO, "Path the system database file created ==> " + lclDbPath)
           
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
            
           # Query the contacts table in the database and get all columns. 
           try:
               stmt = dbConn.createStatement()
               resultSet = stmt.executeQuery("Select tbl_name from SQLITE_MASTER; ")
               self.log(Level.INFO, "query SQLite Master table")
           except SQLException as e:
               self.log(Level.INFO, "Error querying database for system table (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK

           try:
                self.log(Level.INFO, "Begin Create New Artifacts")
                artID_shim = skCase.addArtifactType("TSK_SHIMCACHE", "Shimcache")
           except:		
                self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

           artID_shim = skCase.getArtifactTypeID("TSK_SHIMCACHE")
           artID_shim_evt = skCase.getArtifactType("TSK_SHIMCACHE")
             
             
           # Cycle through each row and create artifacts
           while resultSet.next():
               try: 
                   self.log(Level.INFO, "Result (" + resultSet.getString("tbl_name") + ")")
                   table_name = resultSet.getString("tbl_name")
                   SQL_String_1 = "Select * from " + table_name + ";"
                   SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
				   
                   Column_Names = []
                   Column_Types = []
                   resultSet2  = stmt.executeQuery(SQL_String_2)
                   while resultSet2.next(): 
                      Column_Names.append(resultSet2.getString("name").upper())
                      Column_Types.append(resultSet2.getString("type"))
                      if resultSet2.getString("type").upper() == "TEXT":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_SHIMCACHE_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      else:
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_SHIMCACHE_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
										 
                   resultSet3 = stmt.executeQuery(SQL_String_1)
                   while resultSet3.next():
                      art = file.newArtifact(artID_shim)
                      Column_Number = 1
                      for col_name in Column_Names:
                         c_name = "TSK_SHIMCACHE_" + col_name
                         attID_ex1 = skCase.getAttributeType(c_name)
                         if Column_Types[Column_Number - 1] == "TEXT":
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                         else:
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getInt(Column_Number)))
                         Column_Number = Column_Number + 1

                      # index the artifact for keyword search
                      try:
                          blackboard.indexArtifact(art)
                      except:
                          self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
						
               except SQLException as e:
                   self.log(Level.INFO, "Error getting values from Shimcache table (" + e.getMessage() + ")")

           # Clean up
           stmt.close()
           dbConn.close()
           os.remove(lclDbPath)

        try:
             shutil.rmtree(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + Temp_Dir + "\\Shimcache")
    
    def process_Usnj(self, dataSource, progressBar):
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Set the database to be read to the once created by the SAM parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "$UsnJrnl:$J", "$Extend")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "usnj")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "Usnj Directory already exists " + Temp_Dir)
			
        for file in files:	
           # Check if the user pressed cancel while we were busy
           if self.context.isJobCancelled():
               return IngestModule.ProcessResult.OK

           #self.log(Level.INFO, "Processing file: " + file.getName())
           fileCount += 1

           # Save the DB locally in the temp folder. use file id as name to reduce collisions
           lclDbPath = os.path.join(Temp_Dir, "usnj.txt")
           ContentUtils.writeToFile(file, File(lclDbPath))
           self.log(Level.INFO, "Saved File ==> " + lclDbPath)

           # Run the EXE, saving output to a sqlite database
           self.log(Level.INFO, "Running program ==> " + self.path_to_Usnj_file + " " + os.path.join(Temp_Dir, "usnj.txt") + " " + os.path.join(Temp_Dir, "usnj.db3"))
           pipe = Popen([self.path_to_Usnj_file, os.path.join(Temp_Dir, "usnj.txt"), os.path.join(Temp_Dir, "usnj.db3")], stdout=PIPE, stderr=PIPE)
           out_text = pipe.communicate()[0]
           self.log(Level.INFO, "Output from run is ==> " + out_text)               
               
           # Open the DB using JDBC
           lclDbPath = os.path.join(Temp_Dir, "usnj.db3")
           self.log(Level.INFO, "Path the system database file created ==> " + lclDbPath)
           
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) usnj.db3 (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
            
           # Query the contacts table in the database and get all columns. 
           try:
               stmt = dbConn.createStatement()
               resultSet = stmt.executeQuery("Select tbl_name from SQLITE_MASTER; ")
               self.log(Level.INFO, "query SQLite Master table")
           except SQLException as e:
               self.log(Level.INFO, "Error querying database for system table (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK

           try:
                self.log(Level.INFO, "Begin Create New Artifacts")
                artID_usnj = skCase.addArtifactType("TSK_USNJ", "NTFS UsrJrnl entries")
           except:		
                self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

           artID_usnj = skCase.getArtifactTypeID("TSK_USNJ")
           artID_usnj_evt = skCase.getArtifactType("TSK_USNJ")
             
             
           # Cycle through each row and create artifacts
           while resultSet.next():
               try: 
                   self.log(Level.INFO, "Result (" + resultSet.getString("tbl_name") + ")")
                   table_name = resultSet.getString("tbl_name")
                   SQL_String_1 = "Select * from " + table_name + ";"
                   SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
				   
                   Column_Names = []
                   Column_Types = []
                   resultSet2  = stmt.executeQuery(SQL_String_2)
                   while resultSet2.next(): 
                      Column_Names.append(resultSet2.getString("name").upper())
                      Column_Types.append(resultSet2.getString("type"))
                      if resultSet2.getString("type").upper() == "TEXT":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_USNJ_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      else:
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_USNJ_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
										 
                   resultSet3 = stmt.executeQuery(SQL_String_1)
                   while resultSet3.next():
                      art = file.newArtifact(artID_usnj)
                      Column_Number = 1
                      for col_name in Column_Names:
                         c_name = "TSK_USNJ_" + col_name
                         attID_ex1 = skCase.getAttributeType(c_name)
                         if Column_Types[Column_Number - 1] == "TEXT":
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                         else:
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getInt(Column_Number)))
                         Column_Number = Column_Number + 1
						
                      # index the artifact for keyword search
                      try:
                          blackboard.indexArtifact(art)
                      except:
                          self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                        
               except SQLException as e:
                   self.log(Level.INFO, "Error getting values from Shimcache table (" + e.getMessage() + ")")

        # Clean up
           stmt.close()
           dbConn.close()
           # Fire an event to notify the UI and others that there are new artifacts  
           IngestServices.getInstance().fireModuleDataEvent(
               ModuleDataEvent(Windows_InternalsIngestModuleFactory.moduleName, artID_usnj_evt, None))

           #Clean up EventLog directory and files
           os.remove(lclDbPath)

        try:
             shutil.rmtree(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + Temp_Dir)
    
    def process_Webcache(self, dataSource, progressBar):
       # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "WebcacheV01.dat")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "Webcache")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "Webcache Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir, file.getName() + "-" + str(file.getId()))
            DbPath = os.path.join(Temp_Dir, file.getName() + "-" + str(file.getId()) + ".db3")
            self.log(Level.INFO, file.getName() + ' ==> ' + str(file.getId()) + ' ==> ' + file.getUniquePath()) 
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Run the EXE, saving output to a sqlite database
            self.log(Level.INFO, "Running program on data source parm 1 ==> " + lclDbPath + "  Parm 2 ==> " + DbPath)
            #subprocess.Popen([self.path_to_Webcache_file, lclDbPath, DbPath]).communicate()[0]   
            pipe = Popen([self.path_to_Webcache_file, lclDbPath, DbPath], stdout=PIPE, stderr=PIPE)
            out_text = pipe.communicate()[0]
            self.log(Level.INFO, "Output from run is ==> " + out_text)               

        for file in files:	
           # Open the DB using JDBC
           lclDbPath = os.path.join(Temp_Dir, file.getName() + "-" + str(file.getId()) + ".db3")
           self.log(Level.INFO, "Path the Webcache database file created ==> " + lclDbPath)

           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
            
           try:
               stmt = dbConn.createStatement()
               resultSet = stmt.executeQuery("Select distinct container_name from all_containers;")
               self.log(Level.INFO, "query SQLite Master table")
           except SQLException as e:
               self.log(Level.INFO, "Error querying database for Prefetch table (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
     
           Container_List = []
           while resultSet.next():
              Container_List.append(resultSet.getString("container_name"))
                       
           # Cycle through each row and create artifacts
           for c_name in Container_List:
               try: 
                   container_name = c_name
                   SQL_String_1 = "Select * from all_containers where container_name = '" + container_name + "';"
                   SQL_String_2 = "PRAGMA table_info('All_Containers')"
                   artifact_name = "TSK_WC_" + container_name.upper()
                   artifact_desc = "WebcacheV01 " + container_name.upper()
                   try:
                        self.log(Level.INFO, "Begin Create New Artifacts")
                        artID_web = skCase.addArtifactType( artifact_name, artifact_desc)
                   except:		
                        self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
                   artID_web = skCase.getArtifactTypeID(artifact_name)
                   artID_web_evt = skCase.getArtifactType(artifact_name)
				   
                   Column_Names = []
                   Column_Types = []
                   resultSet2  = stmt.executeQuery(SQL_String_2)
                   while resultSet2.next(): 
                      Column_Names.append(resultSet2.getString("name").upper())
                      Column_Types.append(resultSet2.getString("type").upper())
                      if resultSet2.getString("type").upper() == "TEXT":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute. TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                          except:		
                               self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      elif resultSet2.getString("type").upper() == "":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      else:
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")

										 
                   resultSet3 = stmt.executeQuery(SQL_String_1)
                   while resultSet3.next():
                      art = file.newArtifact(artID_web)
                      Column_Number = 1
                      for col_name in Column_Names:
                         c_name = "TSK_" + col_name
                         attID_ex1 = skCase.getAttrTypeID(c_name)
                         attID_ex1 = skCase.getAttributeType(c_name)
                         if Column_Types[Column_Number - 1] == "TEXT":
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                         elif Column_Types[Column_Number - 1] == "":
                              art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                         else:
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, long(resultSet3.getInt(Column_Number))))
                         Column_Number = Column_Number + 1
                         
                      # index the artifact for keyword search
                      try:
                          blackboard.indexArtifact(art)
                      except:
                          self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
   
                   IngestServices.getInstance().fireModuleDataEvent(
                             ModuleDataEvent(Windows_InternalsIngestModuleFactory.moduleName, artID_web_evt, None))						
               except SQLException as e:
                   self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

           stmt.close()
           dbConn.close()
                   
		#Clean up EventLog directory and files
        for file in files:
            try:
                os.remove(os.path.join(Temp_Dir, file.getName() + "-" + str(file.getId()) + ".db3"))
            except:
			    self.log(Level.INFO, "removal of Webcache file failed " + os.path.join(Temp_Dir, file.getName() + "-" + str(file.getId())))
        try:
             shutil.rmtree(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of Webcache directory failed " + Temp_Dir)

    def process_Shellbags(self, dataSource, progressBar):
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Set the database to be read to the once created by the SAM parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "ntuser.dat", "")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "shellbag")
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "Shellbag Directory already exists " + Temp_Dir)
			
        for file in files:	
           # Check if the user pressed cancel while we were busy
           if self.context.isJobCancelled():
               return IngestModule.ProcessResult.OK

           #self.log(Level.INFO, "Processing file: " + file.getName())
           fileCount += 1

           # Save the DB locally in the temp folder. use file id as name to reduce collisions
           lclDbPath = os.path.join(Temp_Dir, file.getName())
           ContentUtils.writeToFile(file, File(lclDbPath))
           self.log(Level.INFO, "Saved File ==> " + lclDbPath)

           # Run the EXE, saving output to a sqlite database
           self.log(Level.INFO, "Running program ==> " + self.path_to_Shellbags_file + " " + os.path.join(Temp_Dir, file.getName()) + " " + \
                    os.path.join(Temp_Dir, "shellbag_db.db3") + " " + file.getUniquePath())
           pipe = Popen([self.path_to_Shellbags_file, os.path.join(Temp_Dir, file.getName()), os.path.join(Temp_Dir, "Shellbag_db.db3", file.getUniquePath())], stdout=PIPE, stderr=PIPE)
           out_text = pipe.communicate()[0]
           self.log(Level.INFO, "Output from run is ==> " + out_text)               
               
           # Open the DB using JDBC
           lclDbPath = os.path.join(Temp_Dir, "shellbag_db.db3")
           self.log(Level.INFO, "Path the system database file created ==> " + lclDbPath) 
           
           try: 
               Class.forName("org.sqlite.JDBC").newInstance()
               dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
           except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK
            
           # Query the contacts table in the database and get all columns. 
           try:
               stmt = dbConn.createStatement()
               resultSet = stmt.executeQuery("Select tbl_name from SQLITE_MASTER; ")
               self.log(Level.INFO, "query SQLite Master table")
           except SQLException as e:
               self.log(Level.INFO, "Error querying database for system table (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK

           try:
                self.log(Level.INFO, "Begin Create New Artifacts")
                artID_shell = skCase.addArtifactType("TSK_SHELLBAGS", "Shellbags")
           except:		
                self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

           artID_shell = skCase.getArtifactTypeID("TSK_SHELLBAGS")
           artID_shell_evt = skCase.getArtifactType("TSK_SHELLBAGS")
             
             
           # Cycle through each row and create artifacts
           while resultSet.next():
               try: 
                   self.log(Level.INFO, "Result (" + resultSet.getString("tbl_name") + ")")
                   table_name = resultSet.getString("tbl_name")
                   SQL_String_1 = "Select * from " + table_name + ";"
                   SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
				   
                   Column_Names = []
                   Column_Types = []
                   resultSet2  = stmt.executeQuery(SQL_String_2)
                   while resultSet2.next(): 
                      Column_Names.append(resultSet2.getString("name").upper())
                      Column_Types.append(resultSet2.getString("type"))
                      if resultSet2.getString("type").upper() == "TEXT":
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_SHELLBAG_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
                      else:
                          try:
                              attID_ex1 = skCase.addArtifactAttributeType("TSK_SHELLBAG_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet2.getString("name"))
                          except:		
                              self.log(Level.INFO, "Attributes Creation Error, " + resultSet2.getString("name") + " ==> ")
										 
                   resultSet3 = stmt.executeQuery(SQL_String_1)
                   while resultSet3.next():
                      art = file.newArtifact(artID_shell)
                      Column_Number = 1
                      for col_name in Column_Names:
                         c_name = "TSK_SHELLBAG_" + col_name
                         attID_ex1 = skCase.getAttributeType(c_name)
                         if Column_Types[Column_Number - 1] == "TEXT":
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                         else:
                             art.addAttribute(BlackboardAttribute(attID_ex1, Windows_InternalsIngestModuleFactory.moduleName, resultSet3.getInt(Column_Number)))
                         Column_Number = Column_Number + 1
						
                      # index the artifact for keyword search
                      try:
                          blackboard.indexArtifact(art)
                      except:
                          self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
            
               except SQLException as e:
                   self.log(Level.INFO, "Error getting values from Shellbag table (" + e.getMessage() + ")")

        # Clean up
           stmt.close()
           dbConn.close()
           # Fire an event to notify the UI and others that there are new artifacts  
           IngestServices.getInstance().fireModuleDataEvent(
               ModuleDataEvent(Windows_InternalsIngestModuleFactory.moduleName, artID_shell_evt, None))

		#Clean up EventLog directory and files
           #os.remove(lclDbPath)
           for file in files:
              try:
			     os.remove(os.path.join(Temp_Dir, file.getName()))
              except:
			     self.log(Level.INFO, "removal of shellbag file failed " + Temp_Dir + "\\" + file.getName())
        try:
            os.remove(os.path.join(Temp_Dir, "Shellbag_db.db3"))
            shutil.rmtree(Temp_Dir)		
        except:
		    self.log(Level.INFO, "removal of Shellbag directory failed " + Temp_Dir)
    
    
# UI that is shown to user for each ingest job so they can configure the job.
class Windows_InternalsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
    
    def checkBoxEvent(self, event):

        if self.Recentlyused_CB.isSelected():
            self.local_settings.setSetting('Recentlyused_Flag', 'true')
        else:
            self.local_settings.setSetting('Recentlyused_Flag', 'false')

        if self.Filehistory_CB.isSelected():
            self.local_settings.setSetting('Filehistory_Flag', 'true')
        else:
            self.local_settings.setSetting('Filehistory_Flag', 'false')

        if self.Jumplist_CB.isSelected():
            self.local_settings.setSetting('Jumplist_Flag', 'true')
        else:
            self.local_settings.setSetting('Jumplist_Flag', 'false')

        if self.Prefetch_CB.isSelected():
            self.local_settings.setSetting('Prefetch_Flag', 'true')
        else:
            self.local_settings.setSetting('Prefetch_Flag', 'false')

        if self.SAM_CB.isSelected():
            self.local_settings.setSetting('SAM_Flag', 'true')
        else:
            self.local_settings.setSetting('SAM_Flag', 'false')

        if self.Shellbags_CB.isSelected():
            self.local_settings.setSetting('Shellbags_Flag', 'true')
        else:
            self.local_settings.setSetting('Shellbags_Flag', 'false')

        if self.Shimcache_CB.isSelected():
            self.local_settings.setSetting('Shimcache_Flag', 'true')
        else:
            self.local_settings.setSetting('Shimcache_Flag', 'false')

        if self.Usnj_CB.isSelected():
            self.local_settings.setSetting('Usnj_Flag', 'true')
        else:
            self.local_settings.setSetting('Usnj_Flag', 'false')

        if self.Webcache_CB.isSelected():
            self.local_settings.setSetting('Webcache_Flag', 'true')
        else:
            self.local_settings.setSetting('Webcache_Flag', 'false')

    def initComponents(self):
        self.panel0 = JPanel()

        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Recentlyused_CB = JCheckBox( "CCM Recently Used Apps", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Recentlyused_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Recentlyused_CB ) 

        self.Jumplist_CB = JCheckBox( "Parse Jumplist AD", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Jumplist_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Jumplist_CB ) 

        self.Filehistory_CB = JCheckBox( "File History", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Filehistory_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Filehistory_CB ) 

        self.Prefetch_CB = JCheckBox( "Parse Prefetch", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Prefetch_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Prefetch_CB ) 

        self.SAM_CB = JCheckBox( "Parse SAM", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 13 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.SAM_CB, self.gbcPanel0 ) 
        self.panel0.add( self.SAM_CB ) 

        self.Shellbags_CB = JCheckBox( "Parse Shellbags", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Shellbags_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Shellbags_CB ) 

        self.Shimcache_CB = JCheckBox( "Parse Shimcache", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 17 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Shimcache_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Shimcache_CB ) 

        self.Usnj_CB = JCheckBox( "Parse USN Journal", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 19
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Usnj_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Usnj_CB ) 
		
        self.Webcache_CB = JCheckBox( "Parse Webcache", actionPerformed=self.checkBoxEvent) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 21
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Webcache_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Webcache_CB ) 

        self.add(self.panel0)

    def customizeComponents(self):
        self.Jumplist_CB.setSelected(self.local_settings.getSetting('Jumplist_Flag') == 'true')
        self.Filehistory_CB.setSelected(self.local_settings.getSetting('Filehistory_Flag') == 'true')
        self.Prefetch_CB.setSelected(self.local_settings.getSetting('Prefetch_Flag') == 'true')
        self.SAM_CB.setSelected(self.local_settings.getSetting('SAM_Flag') == 'true')
        self.Shellbags_CB.setSelected(self.local_settings.getSetting('Shellbags_Flag') == 'true')
        self.Shimcache_CB.setSelected(self.local_settings.getSetting('Shimcache_Flag') == 'true')
        self.Usnj_CB.setSelected(self.local_settings.getSetting('Usnj_Flag') == 'true')
        self.Webcache_CB.setSelected(self.local_settings.getSetting('Webcache_Flag') == 'true')
        self.Recentlyused_CB.setSelected(self.local_settings.getSetting('Recentlyused_Flag') == 'true')

    # Return the settings used
    def getSettings(self):
        return self.local_settings

