# This python autopsy module will process the Appx installed Programs and add them 
# to the Extracted content Installed Programs
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

# Process_Appx_Programs module to process Appx Programs.
# April 2018
# 
# Comments 
#   Version 1.0 - Initial version - April 2018
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE

from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from java.util import ArrayList
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
from org.sleuthkit.datamodel import CommunicationsManager 
from org.sleuthkit.datamodel import Relationship
from org.sleuthkit.datamodel import Account



# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ProcessAppxProgramsIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Appx_Programs"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses Win Appx Programs"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ProcessAppxProgramsIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ProcessAppxProgramsIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ProcessAppxProgramsIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")

    def startUp(self, context):
        self.context = context
        pass
        
    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # get current case and the store.vol abstract file information
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "staterepository-machine%")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "Appx_Programs")
        #self.log(Level.INFO, "create Directory " + moduleDirectory)
        try:
		    os.mkdir(temporaryDirectory)
        except:
            pass
            #self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)
			
        # Write out each users store.vol file and process it.
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the file locally. Use file id as name to reduce collisions
            extractedFile = os.path.join(temporaryDirectory, file.getName())
            ContentUtils.writeToFile(file, File(extractedFile))
            #os.remove(extractedFile)

        for file in files:	
            #os.remove(extractedFile)
            if file.getName().lower() == "staterepository-machine.srd":
                extractedFile = os.path.join(temporaryDirectory, file.getName())

                artIdInsProg = skCase.getArtifactTypeID("TSK_INSTALLED_PROG")
                artIdInsProgType = skCase.getArtifactType("TSK_INSTALLED_PROG")

                moduleName = ProcessAppxProgramsIngestModuleFactory.moduleName
                
                try: 
                    Class.forName("org.sqlite.JDBC").newInstance()
                    dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % extractedFile)
                except SQLException as e:
                    self.log(Level.INFO, "Could not open database file (not SQLite) " + extractedFile + " (" + e.getMessage() + ")")
                    return IngestModule.ProcessResult.OK

                try:
                    stmt = dbConn.createStatement()
                    resultSet = stmt.executeQuery("select distinct * from (Select packfam.name, packfam.publisher, packfam.publisherid, packuser.user, " + \
                                                  " case Architecture when 0 then 'X64' when 9 then 'x86' when 11 then 'Neutral' else Architecture end Architecture, " + \
                                                  " pack.ResourceId, " + \
                                                  " substr(pack.packageFullName, instr(pack.packageFullName, '_') + 1, instr(substr(pack.packageFullName, instr(pack.packageFullName, '_') + 1), '_') - 1) version, " + \
                                                  " packfam.packageFamilyname,  pack.packageFullName, '??' isFramework, '??' PackageUserInformaton, " + \
                                                  " '??' isResourcePakage, '??' IsBundle, '??' IsDevelopment, '??' Dependicies, '??' IsPartiallyStaged, " + \
                                                  " case SignatureOrigin when 3 then 'System' when 2 then 'Store' else 'Unknown' end SignatureKind, packuser.PackageStatus Status, " + \
                                                  " (substr(packuser.installTime,1,11) -11644473600) InstallTime, packloc.installedLocation " + \
                                                  " from PackageUser packuser, package pack, packageFamily packfam, packageLocation packloc " + \
                                                  " where packuser.package = pack._PackageId and pack.packageFamily = packfam._PackagefamilyId " + \
                                                  " and packloc.package = pack._packageId and (pack.resourceId is null or pack.resourceId = 'neutral')); ")
                    self.log(Level.INFO, "query Appx tables")
                except SQLException as e:
                    self.log(Level.INFO, "Error querying database for appx tables (" + e.getMessage() + ") ")
                    return IngestModule.ProcessResult.OK

                # Cycle through each row and get the installed programs and install time
                while resultSet.next():
                    try: 
                        artInsProg = file.newArtifact(artIdInsProg)
                        attributes = ArrayList()
                        attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, moduleName, resultSet.getString("name")))
                        attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), moduleName, resultSet.getInt("InstallTime")))
               
                        artInsProg.addAttributes(attributes)

                        # index the artifact for keyword search
                        try:
                            blackboard.indexArtifact(artInsProg)
                        except:
                            pass
                    except SQLException as e:
                        self.log(Level.INFO, "Error getting values from Appx tables (" + e.getMessage() + ")")

               # Close the database statement
                try:
                    stmt.close()
                    dbConn.close()
                except:
                    pass                    
			

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Appx Installed Programs", " Appx Installed Programs Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
      
