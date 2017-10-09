# This python autopsy module is an example of the different types of 
# things you can do with Autopsy Pythin plugin
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

# Logical_Files module.
# February 2017
# 
# Comments 
#   Version 1.0 - Initial version - Feb 2017
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE

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
from org.sleuthkit.datamodel import Image
from org.sleuthkit.datamodel.TskData import DbType
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestManager
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest import ModuleContentEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule import AddLocalFilesTask
from org.sleuthkit.autopsy.casemodule.services.FileManager import FileAddProgressUpdater
from org.sleuthkit.autopsy.ingest import ModuleContentEvent;

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
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
    
class VSSIngesttModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Process/Extract Volume Shadow"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Process/Extract Volume Shadow"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return VSSIngesttModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class VSSIngesttModule(DataSourceIngestModule):

    _logger = Logger.getLogger(VSSIngesttModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_Logical_Files = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        
        #self.logger.logp(Level.INFO, Logical_FilesWithUI.__name__, "startUp", str(self.List_Of_Events))
        #self.log(Level.INFO, str(self.List_Of_Logical_Files))
        self.path_to_exe_vss = os.path.join(os.path.dirname(os.path.abspath(__file__)), "process_extract_vss.exe")
        if not os.path.exists(self.path_to_exe_vss):
            raise IngestModuleException("Process_Extract_vss File to Run/execute does not exist.")

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
        
        skCase = Case.getCurrentCase().getSleuthkitCase();
        
        self.log(Level.INFO, "Starting Processing of Image")

        image_names = dataSource.getPaths()
        self.log(Level.INFO, "Image names ==> " + str(image_names[0]))
        image_name = str(image_names[0])
        
  		# Create VSS directory in ModuleOutput directory, if it exists then continue on processing		
        Mod_Dir = Case.getCurrentCase().getModulesOutputDirAbsPath()
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        vss_output = os.path.join(Mod_Dir, "vss")

        try:
		    os.mkdir(vss_output)
        except:
		    self.log(Level.INFO, "Vss already exists " + Temp_Dir)
            
        lclDbPath = os.path.join(vss_output, "vss_extract_info.db3")
        vss_error_log = os.path.join(vss_output, "bad_files.log")

        # Run the Processing/Extraction process
        self.log(Level.INFO, "Running prog ==> " + self.path_to_exe_vss + " " + image_name + " " + lclDbPath + " " + vss_output + " " + vss_error_log)
        pipe = Popen([self.path_to_exe_vss, image_name, lclDbPath, vss_output, vss_error_log], stdout=PIPE, stderr=PIPE)
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text)               

        try:
            attID_vs_fn = skCase.addArtifactAttributeType("TSK_VSS_MFT_NUMBER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MFT Number")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, MFT Number. ==> ")
        try:
            attID_vs_ct = skCase.addArtifactAttributeType("TSK_VSS_DATETIME_CHANGED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Recovered Record")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, changed time. ==> ")
        try:
            attID_vs_sz = skCase.addArtifactAttributeType("TSK_VSS_FILE_SIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "File Size")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Computer Name. ==> ")

      
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file (not SQLite) " +" (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK

        try:
            stmt = dbConn.createStatement()
            SQL_Statement = "select ' - '||vss_identifier||' - '||DATETIME((SUBSTR(vss_create_dttm,1,11)-11644473600),'UNIXEPOCH') 'VOL_NAME', " + \
                            " vss_num, volume_id, vss_identifier from vss_info;"
            self.log(Level.INFO, "SQL Statement " + SQL_Statement + "  <<=====")
            resultSet = stmt.executeQuery(SQL_Statement)
        except SQLException as e:
            self.log(Level.INFO, "Error querying database for EventLogs table (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK

        # Cycle through each row and create artifacts
        while resultSet.next():
     
            dir_list = []
            vss_identifier = resultSet.getString("vss_identifier")
            vss_num = int(resultSet.getString("vss_num")) - 1
            dir_list.append(vss_output + "\\vss" + str(vss_num))
        
            services = IngestServices.getInstance()
        
            progress_updater = ProgressUpdater()  
            newDataSources = []        
         
            # skCase = Case.getCurrentCase().getSleuthkitCase();
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            skcase_data = Case.getCurrentCase()
        
            # Get a Unique device id using uuid
            device_id = UUID.randomUUID()
            self.log(Level.INFO, "device id: ==> " + str(device_id))

            skcase_data.notifyAddingDataSource(device_id)
            
            # Add data source with files
            newDataSource = fileManager.addLocalFilesDataSource(str(device_id), "vss" + str(vss_num) + resultSet.getString("VOL_NAME"), "", dir_list, progress_updater)
            
            newDataSources.append(newDataSource.getRootDirectory())
           
            # Get the files that were added
            files_added = progress_updater.getFiles()
            #self.log(Level.INFO, "Fire Module1: ==> " + str(files_added))
            
            for file_added in files_added:
                skcase_data.notifyDataSourceAdded(file_added, device_id)
                #self.log(Level.INFO, "Fire Module1: ==> " + str(file_added))

            #skcase.notifyDataSourceAdded(device_id)

            skCse = Case.getCurrentCase().getSleuthkitCase()
            vss_fileManager = Case.getCurrentCase().getServices().getFileManager()
            vss_files = fileManager.findFiles(dataSource, "%" + vss_identifier + "%", "System Volume Information")
            vss_numFiles = len(vss_files)
   
            #self.log(Level.INFO, "Number of VSS FIles is ==> " + str(vss_numFiles) + " <<= FIle Name is ++> " + str(vss_files))

            for vs in vss_files:
                 if vs.getName() in "-slack":
                     pass            
            try:
                 self.log(Level.INFO, "Begin Create New Artifacts")
                 artID_vss = skCase.addArtifactType( "TSK_VS_VOLUME_" + str(vss_num), "vss" + str(vss_num) + resultSet.getString("VOL_NAME") + " Files")
            except:		
                 self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
                 artID_vss = skCase.getArtifactTypeID("TSK_VS_VOLUME_" + str(vss_num))

            artID_vss = skCase.getArtifactTypeID("TSK_VS_VOLUME_" + str(vss_num))
            artID_vss_evt = skCase.getArtifactType("TSK_VS_VOLUME_" + str(vss_num))
            attID_vs_fn = skCase.getAttributeType("TSK_VSS_MFT_NUMBER")
            attID_vs_ct = skCase.getAttributeType("TSK_VSS_DATETIME_CHANGED")			 
            attID_vs_sz = skCase.getAttributeType("TSK_VSS_FILE_SIZE")			 
            attID_vs_nm = skCase.getAttributeType("TSK_NAME")
            attID_vs_pa = skCase.getAttributeType("TSK_PATH")
            attID_vs_md = skCase.getAttributeType("TSK_DATETIME_MODIFIED")
            attID_vs_ad = skCase.getAttributeType("TSK_DATETIME_ACCESSED")
            attID_vs_cr = skCase.getAttributeType("TSK_DATETIME_CREATED")
            
            for vs_file in vss_files:
                if "-slack" in vs_file.getName():
                    pass            
                else:
                    self.log(Level.INFO, "VSS FIles is ==> " + str(vs_file))
      
                    try:
                        stmt_1 = dbConn.createStatement()
                        SQL_Statement_1 = "select file_name, inode, directory, ctime, mtime, atime, crtime, size " + \
                                          " from vss1_diff where lower(f_type) <> 'dir';"
                        self.log(Level.INFO, "SQL Statement " + SQL_Statement_1 + "  <<=====")
                        resultSet_1 = stmt_1.executeQuery(SQL_Statement_1)
                    except SQLException as e:
                        self.log(Level.INFO, "Error querying database for vss diff tables (" + e.getMessage() + ")")
                        return IngestModule.ProcessResult.OK

                    # Cycle through each row and create artifacts
                    while resultSet_1.next():
                        try: 
                            File_Name  = resultSet_1.getString("file_name")
                            Path_Name = resultSet_1.getString("directory")
                            MFT_Number = resultSet_1.getString("inode")
                            Ctime = resultSet_1.getInt("ctime")
                            Mtime = resultSet_1.getInt("mtime")
                            Atime = resultSet_1.getInt("atime")
                            Crtime = resultSet_1.getInt("crtime")
                            File_Size = resultSet_1.getInt("size")
                        except SQLException as e:
                            self.log(Level.INFO, "Error getting values from vss diff table (" + e.getMessage() + ")")
                
                        # Make an artifact on the blackboard, TSK_PROG_RUN and give it attributes for each of the fields
                        # Make artifact for TSK_EVTX_LOGS
                        art = vs_file.newArtifact(artID_vss)

                        art.addAttributes(((BlackboardAttribute(attID_vs_nm, VSSIngesttModuleFactory.moduleName, File_Name)), \
                                           (BlackboardAttribute(attID_vs_fn, VSSIngesttModuleFactory.moduleName, MFT_Number)), \
                                           (BlackboardAttribute(attID_vs_pa, VSSIngesttModuleFactory.moduleName, Path_Name)), \
                                           (BlackboardAttribute(attID_vs_cr, VSSIngesttModuleFactory.moduleName, Crtime)), \
                                           (BlackboardAttribute(attID_vs_md, VSSIngesttModuleFactory.moduleName, Mtime)), \
                                           (BlackboardAttribute(attID_vs_ad, VSSIngesttModuleFactory.moduleName, Atime)), \
                                           (BlackboardAttribute(attID_vs_ct, VSSIngesttModuleFactory.moduleName, Ctime)),
                                           (BlackboardAttribute(attID_vs_sz, VSSIngesttModuleFactory.moduleName, File_Size))))
                        
                    # Fire an event to notify the UI and others that there are new artifacts  
                    IngestServices.getInstance().fireModuleDataEvent(
                        ModuleDataEvent(VSSIngesttModuleFactory.moduleName, artID_vss_evt, None))

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Process/Extract VS", " Volume Shadow has been analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

