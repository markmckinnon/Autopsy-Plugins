# This python autopsy module will execute Volatility against a memory image.  
# It will ask the user for the directory where the Volatility executables reside 
# then it will run volatility against the memory image using options the 
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

# Volatility.
# April 2017
# 
# Comments 
#   Version 1.0 - Initial version - April 2017
#   Version 1.1 - Add code that will import the dumped files as derived files under the memory image.
#                 Fix the code when imageinfo is selected.
#   Version 1.2 - Fix spelling error for dervived file to derived.  More code clean needed
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
from javax.swing import JList
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import JComboBox
from javax.swing.filechooser import FileNameExtensionFilter
#from java.awt.event import KeyListener;

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
from org.sleuthkit.autopsy.ingest import IngestJobContext
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest import ModuleContentEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class VolatilityDumpIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Volatility Dump File Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Dump Files Using Volatility against a Memory Image"
    
    def getModuleVersionNumber(self):
        return "1.2"
    
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
        self.Process_Ids_To_Dump = ""
        self.Python_Program = False
        self.Volatility_Version = ""
        self.List_df = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        #Show parameters that are passed in
        self.Volatility_Executable = self.local_settings.getVolatility_Directory()
        self.Plugins = self.local_settings.getPluginListBox()
        self.Profile = self.local_settings.getProfile()
        self.Volatility_Version = self.local_settings.getVersion()
        #self.Process_Ids_To_Dump = self.local_settings.getProcessIDs()
        
        Pids = self.local_settings.getProcessIDs()
        
        if Pids == "":
            pass
        else:
            self.Process_Ids_To_Dump = Pids.split(",")
        
        if self.Profile == 'Autodetect':
            self.isAutodetect = True
        else:
            self.isAutodetect = False
        
        self.log(Level.INFO, "Volatility Executable ==> " + self.local_settings.getVolatility_Directory())
        self.log(Level.INFO, "Volatility Profile to use ==> " + self.Profile)
        self.log(Level.INFO, "Volatility Plugins to use ==> " + str(self.Plugins))
        self.log(Level.INFO, "Additional Parms ==> " + str(self.Process_Ids_To_Dump) + "<<")
        self.log(Level.INFO, "Additional Parms ==> " + Pids + "<<")
        
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

        self.log(Level.INFO, "Starting to process, Just before call to parse_safari_history")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Get the temp directory and create the sub directory
        Temp_Dir = Case.getCurrentCase().getModulesOutputDirAbsPath()
        try:
		    os.mkdir(Temp_Dir + "\Volatility\\Dump-Files")
        except:
		    self.log(Level.INFO, "Volatility Directory already exists " + Temp_Dir)
        self.log(Level.INFO, "Volatility Directory already exists " + str(dataSource.getId()))
        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%", "/")
        numFiles = len(files)
        self.log(Level.INFO, "Number of files to process ==> " + str(numFiles))
        #file_name = os.path.basename(self.path_to_storage_file)
        #self.log(Level.INFO, "File Name ==> " + file_name)
        #base_file_name = os.path.splitext(file_name)[0]
        
        for file in files:
            if '/LogicalFileSet1/' == file.parentPath:
                self.log(Level.INFO, "File name to process is ==> " + str(file))
                self.log(Level.INFO, "File name to process is ==> " + str(file.getLocalAbsPath()))

                mem_abstract_file_info = skCase.getAbstractFileById(file.getId())

                image_file = file.getLocalAbsPath()
                if image_file != None:
                    self.log(Level.INFO, "File name to process is ==> " + str(file.getLocalAbsPath()))
                    file_name = os.path.basename(file.getLocalAbsPath())
                    base_file_name = os.path.splitext(file_name)[0]
                    self.database_file = Temp_Dir + "\\volatility\\" + base_file_name + ".db3"
                    # self.log(Level.INFO, "File Name ==> " + self.database_file)
                    derived_dir = "ModuleOutput\\volatility\\Dump-Files\\"
                    dump_file = Temp_Dir + "\\volatility\\Dump-Files"
                    if self.isAutodetect:
                        self.find_profile(image_file)
                    if self.Profile == None:
                        continue
                    for plugin_to_run in self.Plugins:
                        plugin_dir = os.path.join(dump_file, plugin_to_run)
                        try:
                            os.mkdir(plugin_dir)
                        except:
                            pass
                        if self.Python_Program:    
                            if self.Process_Ids_To_Dump == "":
                                new_derived_dir = self.add_Volatility_Dump_dir(dataSource, mem_abstract_file_info, dump_file, plugin_to_run, derived_dir)
                                self.log(Level.INFO, "Running program ==> " + self.Volatility_Executable + " -f " + file.getLocalAbsPath() + " " + \
                                     "--profile=" + self.Profile + " --dump-dir=" + plugin_dir + " " + plugin_to_run)
                                pipe = Popen(["Python.exe", self.Volatility_Executable, "-f", file.getLocalAbsPath(), "--profile=" + self.Profile, \
                                   "--dump-dir=" + plugin_dir, plugin_to_run], stdout=PIPE, stderr=PIPE)
                                out_text = pipe.communicate()[0]
                                self.log(Level.INFO, "Output from run is ==> " + out_text)               
                                self.add_Volatility_Dump_file(dataSource, new_derived_dir, plugin_dir, derived_dir + "\\" + plugin_to_run)
                            else:
                                for pid_to_run in self.Process_Ids_To_Dump:
                                    new_derived_dir = self.add_Volatility_Dump_dir(dataSource, mem_abstract_file_info, dump_file, plugin_to_run, derived_dir)                        
                                    pid_dir = os.path.join(plugin_dir, pid_to_run.lstrip())
                                    try:
                                        os.mkdir(pid_dir)
                                    except:
                                        pass
                                    new_derived_dir_pid = self.add_Volatility_Dump_dir(dataSource, new_derived_dir, pid_dir, pid_to_run.lstrip(), derived_dir + "\\" + plugin_to_run)
                                    self.log(Level.INFO, "Running program ==> " + self.Volatility_Executable + " -f " + file.getLocalAbsPath() + " " + \
                                         "--profile=" + self.Profile + " --dump-dir=" + pid_dir + " --pid=" + pid_to_run.lstrip() + " " + plugin_to_run)
                                    pipe = Popen(["Python.exe", self.Volatility_Executable, "-f", file.getLocalAbsPath(), "--profile=" + self.Profile, \
                                       "--dump-dir=" + pid_dir, "--pid=" + pid_to_run.lstrip(), plugin_to_run], stdout=PIPE, stderr=PIPE)
                                    out_text = pipe.communicate()[0]
                                    self.log(Level.INFO, "Output from run is ==> " + out_text)               
                                    self.add_Volatility_Dump_file(dataSource, new_derived_dir_pid, pid_dir, derived_dir + "\\" + plugin_to_run + "\\" + pid_to_run.lstrip(), pid_to_run.lstrip())
                        else:
                            if self.Process_Ids_To_Dump == "":
                                new_derived_dir = self.add_Volatility_Dump_dir(dataSource, mem_abstract_file_info, dump_file, plugin_to_run, derived_dir)
                                self.log(Level.INFO, "Running program ==> " + self.Volatility_Executable + " -f " + file.getLocalAbsPath() + " " + \
                                     "--profile=" + self.Profile + " --dump-dir=" + plugin_dir + " " + plugin_to_run)
                                pipe = Popen([self.Volatility_Executable, "-f", file.getLocalAbsPath(), "--profile=" + self.Profile, \
                                     "--dump-dir=" + plugin_dir, plugin_to_run], stdout=PIPE, stderr=PIPE)
                                out_text = pipe.communicate()[0]
                                self.log(Level.INFO, "Output from run is ==> " + out_text)               
                                self.add_Volatility_Dump_file(dataSource, new_derived_dir, plugin_dir, derived_dir + "\\" + plugin_to_run, " ")
                            else:            
                                for pid_to_run in self.Process_Ids_To_Dump:
                                    new_derived_dir = self.add_Volatility_Dump_dir(dataSource, mem_abstract_file_info, dump_file, plugin_to_run, derived_dir)                        
                                    pid_dir = os.path.join(plugin_dir, pid_to_run.lstrip())
                                    try:
                                        os.mkdir(pid_dir)
                                    except:
                                        pass
                                    new_derived_dir_pid = self.add_Volatility_Dump_dir(dataSource, new_derived_dir, plugin_dir, pid_to_run.lstrip(), derived_dir + "\\" + plugin_to_run)
                                    self.log(Level.INFO, "Running program ==> " + self.Volatility_Executable + " -f " + file.getLocalAbsPath() + " " + \
                                         "--profile=" + self.Profile + " --dump-dir=" + pid_dir + " --pid=" + pid_to_run.lstrip() + " " + plugin_to_run)
                                    pipe = Popen([self.Volatility_Executable, "-f", file.getLocalAbsPath(), "--profile=" + self.Profile, \
                                         "--dump-dir=" + pid_dir, "--pid=" + pid_to_run.lstrip(), plugin_to_run], stdout=PIPE, stderr=PIPE)
                                    out_text = pipe.communicate()[0]
                                    self.log(Level.INFO, "Output from run is ==> " + out_text)               
                                    self.add_Volatility_Dump_file(dataSource, new_derived_dir_pid, pid_dir, derived_dir + "\\" + plugin_to_run + "\\" + pid_to_run.lstrip(), pid_to_run.lstrip())

                
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "VolatilitySettings", " VolatilitySettings Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    def find_profile(self, image_file):

        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)

        self.log(Level.INFO, "File name to process is ==> " + str(image_file))
        file_name = os.path.basename(image_file)
        self.log(Level.INFO, "File Name ==> " + file_name)
        base_file_name = os.path.splitext(file_name)[0]
        #database_file = Temp_Dir + "\\" + base_file_name + ".db3"
        self.log(Level.INFO, "File Name ==> " + self.database_file)
        
        found_profile = False
        
        if os.path.isfile(self.database_file):
            self.log(Level.INFO, "Path the volatility database file created ==> " + self.database_file)
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % self.database_file)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + self.database_file + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the database 
            try:
                stmt = dbConn.createStatement()
                resultSet1 = stmt.executeQuery('Select "Suggested Profile(s)" from imageinfo')
                self.log(Level.INFO, "query " + str(resultSet1))
                # Cycle through each row and create artifacts
                profile_names = None
                while resultSet1.next():
                    try:
                       profile_names = resultSet1.getString("Suggested Profile(s)")
                       if profile_names == None:
                           self.Profile = None
                       elif ',' in profile_names:
                           profile_list = profile_names.split(",")
                           self.Profile = profile_list[0]
                       elif ' ' in profle_names:
                           profile_list = profile_names.split(" ")
                           self.Profile = profile_list[0]
                       else:
                           self.Profile = profile_names
                       found_profile = True    
                    except:
                       self.log(Level.INFO, "Error getting profile name, Profile name is ==> " + profile_names + " <==")
            except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) " + self.database_file + " (" + e.getMessage() + ")")

            try:
                 stmt.close()
                 dbConn.close()
                 #os.remove(database_name)		
            except:
                 self.log(Level.INFO, "removal of volatility imageinfo database failed " + Temp_Dir)
        
        if found_profile:
            pass
        else:
            if self.Python_Program:
                self.log(Level.INFO, "Running program ==> " + "Python " + self.Volatility_Executable + " -f " + image_file + " " + \
                         " --output=sqlite --output-file=" + self.database_file + " imageinfo")
                pipe = Popen(["Python.exe", self.Volatility_Executable, "-f", image_file, "--output=sqlite", \
                       "--output-file=" + self.database_file, "imageinfo"], stdout=PIPE, stderr=PIPE)
            else:
                self.log(Level.INFO, "Running program ==> " + self.Volatility_Executable + " -f " + image_file + " " + \
                         " --output=sqlite --output-file=" + self.database_file + " imageinfo")
                pipe = Popen([self.Volatility_Executable, "-f", image_file, "--output=sqlite", \
                       "--output-file=" + self.database_file, "imageinfo"], stdout=PIPE, stderr=PIPE)
            
            out_text = pipe.communicate()[0]
            self.log(Level.INFO, "Output from run is ==> " + out_text)               

            # Open the DB using JDBC
            self.log(Level.INFO, "Path the volatility database file created ==> " + self.database_file)
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % self.database_file)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + self.database_file + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the database 
            try:
                stmt = dbConn.createStatement()
                resultSet1 = stmt.executeQuery('Select "Suggested Profile(s)" from imageinfo')
                self.log(Level.INFO, "query SQLite Master table ==> " )
                self.log(Level.INFO, "query " + str(resultSet1))
                # Cycle through each row and create artifacts
                profile_names = None
                while resultSet1.next():
                    try:
                       profile_names = resultSet1.getString("Suggested Profile(s)")
                       if profile_names == None:
                           self.Profile = None
                       elif ',' in profile_names:
                           profile_list = profile_names.split(",")
                           self.Profile = profile_list[0]
                       elif ' ' in profle_names:
                           profile_list = profile_names.split(" ")
                           self.Profile = profile_list[0]
                       else:
                           self.Profile = profile_names
                           
                    except:
                       self.log(Level.INFO, "Error getting profile name, Profile name is ==> " + profile_names + " <==")
            except SQLException as e:
               self.log(Level.INFO, "Could not open database file (not SQLite) " + self.database_file + " (" + e.getMessage() + ")")
               return IngestModule.ProcessResult.OK

            try:
                 stmt.close()
                 dbConn.close()
                 #os.remove(database_name)		
            except:
                 self.log(Level.INFO, "removal of volatility imageinfo database failed " + Temp_Dir)
   
    def add_Volatility_Dump_dir(self, dataSource, dir_abstract_file_info, dump_dir, dir_name, local_dir):
    
        skCase = Case.getCurrentCase().getSleuthkitCase()
        self.log(Level.INFO, " dir Name is ==> " + dir_name)
        self.log(Level.INFO, " abstract parentPath is ==> " + str(dir_abstract_file_info.parentPath))
        self.log(Level.INFO, "Dump Dir is ==> " + dump_dir)
        self.log(Level.INFO, "Local Directory is ==> " + local_dir)
        
        dev_file = os.path.join(dump_dir, dir_name)
        local_file = os.path.join(local_dir, dir_name)
        
        if not(self.check_derived_existance(dataSource, dir_name, dir_abstract_file_info.parentPath)):
        
            # Add derived file
            # Parameters Are:
            #    File Name, Local Path, size, ctime, crtime, atime, mtime, isFile, Parent File, rederive Details, Tool Name, 
            #     Tool Version, Other Details, Encoding Type
            derived_file = skCase.addDerivedFile(dir_name, local_file, os.path.getsize(dev_file), + \
                                     0, 0, 0, 0, True, dir_abstract_file_info, "", "Volatility", self.Volatility_Version, "", TskData.EncodingType.NONE)
            IngestServices.getInstance().fireModuleContentEvent(ModuleContentEvent(derived_file))
#            self.context.addFilesToJob(df_list)
            #self.log(Level.INFO, "Derived File ==> " + str(derived_file))
        else:
            pass                

        #self.log(Level.INFO, " derived File Is ==> " + str(derived_file))
        
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        new_derived_file = fileManager.findFiles(dataSource, dir_name, dir_abstract_file_info.parentPath)
        numFiles = len(new_derived_file)
    
        self.log(Level.INFO, " print number of files is " + str(numFiles))
        
        for file in new_derived_file:
            self.log(Level.INFO, "File Exists ==> " + str(file))
            self.log(Level.INFO, "Local Directory ==> " + str(file.localPath))
            self.log(Level.INFO, "Local Directory ==> " + local_file)
            if local_file == file.localPath:
                self.log(Level.INFO, "File Exists ==> " + str(file))
                return file
                
        self.log(Level.INFO, "File Exists2 ==> " + str(new_derived_file[0]))   
        return new_derived_file[0]

    def add_Volatility_Dump_file(self, dataSource, dir_abstract_file_info, dump_dir, local_dir, pid_name):
    
    
        self.log(Level.INFO, "Adding Files from Dump Directory")
        self.log(Level.INFO, "Dump Dir is ==> " + dump_dir)
        self.log(Level.INFO, "Local Directory is ==> " + local_dir)
        self.log(Level.INFO, "Parent Path is ==> " + str(dir_abstract_file_info))
                
        #skCase = Case.getCurrentCase().getSleuthkitCase()
        skCase = Case.getCurrentCase().getServices().getFileManager()
        files = next(os.walk(dump_dir))[2]
        for file in files:
            self.log(Level.INFO, " File Name is ==> " + file)
            
            dev_file = os.path.join(dump_dir, file)
            local_file = os.path.join(local_dir, file)
            self.log(Level.INFO, " Dev File Name is ==> " + dev_file)
            self.log(Level.INFO, " Local File Name is ==> " + local_file)
            
            if not(self.check_derived_existance(dataSource, file, dir_abstract_file_info.parentPath)):
            
                # Add derived file
                # Parameters Are:
                #    File Name, Local Path, size, ctime, crtime, atime, mtime, isFile, Parent File, rederive Details, Tool Name, 
                #     Tool Version, Other Details, Encoding Type
                derived_file = skCase.addDerivedFile(file, local_file, os.path.getsize(dev_file), + \
                                         0, 0, 0, 0, True, dir_abstract_file_info, "", "Volatility", self.Volatility_Version, "", TskData.EncodingType.NONE)
                    IngestServices.getInstance().fireModuleContentEvent(ModuleContentEvent(derived_file))
                #self.log(Level.INFO, "Derived File ==> " + str(derived_file))
            else:
                pass                
    
    def check_derived_existance(self, dataSource, file_name, parent_file_path):

        self.log(Level.INFO, "File Name is ==> " + str(file_name) + "  <==> Parent File Dir ==> " + str(parent_file_path))
        
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        derived_file = fileManager.findFiles(dataSource, file_name, parent_file_path)
        numFiles = len(derived_file)
    
        if numFiles == 0:
            self.log(Level.INFO, "File Does Not Exists ==> " + str(file_name))
            return False
        else:
            for file in derived_file:
                self.log(Level.INFO, "File Exists ==> " + str(file_name))
                if parent_file_path == file.parentPath:
                    self.log(Level.INFO, "File Exists ==> " + str(file_name))
                    return True
            self.log(Level.INFO, "File Does Not Exists ==> " + str(file_name))
            return False

    # def get_abstract_file(self, dataSource, file_name, dir_name):

        # fileManager = Case.getCurrentCase().getServices().getFileManager()
        # abstract_files = fileManager.findFiles(dataSource, file_name, dir_name)
        # numFiles = len(abstract_files)
        # asf_list = []
    
        # self.log(Level.INFO, " print number of files is " + str(numFiles))
        
        # for file in abstract_files:
            # self.log(Level.INFO, "File Exists ==> " + str(dir_name) + " Parent Path ==> " + file.parentPath)
            # if dir_name == file.parentPath:
                # self.log(Level.INFO, "File Exists ==> " + str(file))
                # return asf_list.append(file)
                
        # self.log(Level.INFO, "File Exists2 ==> " + str(file))   
        # return None
        
# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class VolatilitySettingsWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.Volatility_Dir_Found = False
        self.Volatility_Directory = ""
        self.Exclude_File_Sources = False
        self.Version = "2.5"
        self.Profile = "Autodetect" 
        self.Plugins = []
        self.AdditionalParms = ""
        self.ProcessIDs = ""
       
    def getVersionNumber(self):
        return serialVersionUID

    # Define getters and settings for data you want to store from UI
    def getVolatility_Dir_Found(self):
        return self.Volatility_Dir_Found

    def setVolatility_Dir_Found(self, flag):
        self.Volatility_Dir_Found = flag

    def getVolatility_Directory(self):
        return self.Volatility_Directory

    def setVolatility_Directory(self, dirname):
        self.Volatility_Directory = dirname

    def getVersion(self):
        return self.Version

    def setVersion(self, entry):
        self.Version = entry
        
    def getProfile(self):
        return self.Profile

    def setProfile(self, entry):
        self.Profile = entry
        
    def getPluginListBox(self):
        return self.Plugins

    def setPluginListBox(self, entry):
        self.Plugins = entry
        
    def clearPluginListBox(self):
        self.Plugins[:] = []
        
    def getProcessIDs(self):
        return self.ProcessIDs

    def setProcessIDs(self, entry):
        self.ProcessIDs = entry
        

    
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
    
    # Check the checkboxs to see what actions need to be taken
    def checkBoxEvent(self, event):
        if self.Exclude_File_Sources_CB.isSelected():
            self.local_settings.setExclude_File_Sources(True)
        else:
            self.local_settings.setExclude_File_Sources(False)

            
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
               if resultSet.getString("Setting_Name") == "Volatility_Version":
                   self.Version_CB.setSelectedItem(resultSet.getString("Setting_Value"))
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
               SQL_Statement2 = 'Update settings set Setting_Value = "' + self.Version_CB.getSelectedItem() + '"' + \
                               ' where setting_name = "Volatility_Version";' 
           else:
               SQL_Statement = 'Insert into settings (Setting_Name, Setting_Value) values ("Volatility_Executable_Directory", "' +  \
                               self.Program_Executable_TF.getText() + '");' 
               SQL_Statement2 = 'Insert into settings (Setting_Name, Setting_Value) values ("Volatility_Version", "' +  \
                               self.Version_CB.getSelectedItem() + '");' 
           
           stmt.execute(SQL_Statement)
           stmt.execute(SQL_Statement2)
           self.Error_Message.setText("Volatility Executable Directory Saved")
           self.local_settings.setVolatility_Directory(self.Program_Executable_TF.getText())
        except SQLException as e:
           self.Error_Message.setText(e.getMessage())
        stmt.close()
        dbConn.close()
           
    def get_plugins(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\GUI_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
            self.Error_Message.setText("Database opened")
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings DB!")
 
        try:
           stmt = dbConn.createStatement()
           SQL_Statement = "select plugin_name from plugins where volatility_version = '" + self.Version_CB.getSelectedItem() + "' and " + \
                            " plugin_name in ('dumpcerts', 'dumpfiles', 'dumpregistry', 'linux_librarydump', 'linux_procdump', 'mac_dump_file', 'mac_procdump', 'moddump', 'procdump', 'vaddump');" 
           resultSet = stmt.executeQuery(SQL_Statement)
           plugin_list = []
           while resultSet.next():
              plugin_list.append(resultSet.getString("plugin_name"))

           stmt.close()
           dbConn.close()
           return plugin_list
        except SQLException as e:
            self.Error_Message.setText("Error Reading plugins")
            stmt.close()
            dbConn.close()
            return "Error"

    def get_profiles(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\GUI_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
            self.Error_Message.setText("Database opened")
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings DB!")
 
        try:
           stmt = dbConn.createStatement()
           SQL_Statement = "select profile_name from profiles where volatility_version = '" + self.Version_CB.getSelectedItem() + "' order by 1;" 
           resultSet = stmt.executeQuery(SQL_Statement)
           profile_list = []
           while resultSet.next():
              profile_list.append(resultSet.getString("profile_name"))

           stmt.close()
           dbConn.close()
           return profile_list
        except SQLException as e:
            self.Error_Message.setText("Error Reading plugins")
            stmt.close()
            dbConn.close()
            return "Error"

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
        
    def onchange_version(self, event):
        self.local_settings.setVersion(event.item)        
        plugin_list = self.get_plugins()
        profile_list = self.get_profiles()
        self.Profile_CB.removeAllItems()
        self.Plugin_LB.clearSelection()
        self.Plugin_LB.setListData(plugin_list)
        for profile in profile_list:
            self.Profile_CB.addItem(profile)
        #self.Profile_CB.addItems(profile)
        self.panel0.repaint()
        
    def onchange_plugins_lb(self, event):
        self.local_settings.clearPluginListBox()
        list_selected = self.Plugin_LB.getSelectedValuesList()
        self.local_settings.setPluginListBox(list_selected)      

    def onchange_profile_cb(self, event):
        self.local_settings.setProfile(event.item) 

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

        self.Version_Label_1 = JLabel( "Version:") 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Version_Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Version_Label_1 ) 
        
        self.Version_List = ("2.5", "2.6") 
        self.Version_CB = JComboBox( self.Version_List)
        self.Version_CB.itemStateChanged = self.onchange_version        
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 11 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Version_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Version_CB ) 

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

        self.Plugin_Label_1 = JLabel( "Plugins:") 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Plugin_Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Plugin_Label_1 ) 
        
        self.Plugin_list = self.get_plugins()
        self.Plugin_LB = JList( self.Plugin_list, valueChanged=self.onchange_plugins_lb)
        self.Plugin_LB.setVisibleRowCount( 3 ) 
        self.scpPlugin_LB = JScrollPane( self.Plugin_LB ) 
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 15 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 1 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.scpPlugin_LB, self.gbcPanel0 ) 
        self.panel0.add( self.scpPlugin_LB ) 

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

        self.Profile_Label_1 = JLabel( "Profile:") 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 19
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Profile_Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Profile_Label_1 ) 
        
        self.Profile_List = self.get_profiles()
        self.Profile_CB = JComboBox( self.Profile_List)
        self.Profile_CB.itemStateChanged = self.onchange_profile_cb        
        self.gbcPanel0.gridx = 6 
        self.gbcPanel0.gridy = 19 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 1 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Profile_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Profile_CB ) 

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

        self.Label_2 = JLabel("Process ids to dump (comma seperated list):")
        self.Label_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 23 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_2, self.gbcPanel0 ) 
        self.panel0.add( self.Label_2 ) 

        self.Process_Ids_To_Dump_TF = JTextField(10,focusLost=self.keyPressed) 
        #self.Process_Ids_To_Dump_TF.getDocument().addDocumentListener()
        self.Process_Ids_To_Dump_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 25 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Process_Ids_To_Dump_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Process_Ids_To_Dump_TF ) 

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
        #self.Exclude_File_Sources_CB.setSelected(self.local_settings.getExclude_File_Sources())
        #self.Run_Plaso_CB.setSelected(self.local_settings.getRun_Plaso())
        #self.Import_Plaso_CB.setSelected(self.local_settings.getImport_Plaso())
        self.check_Database_entries()
        #pass
        
    # Return the settings used
    def getSettings(self):
        return self.local_settings

