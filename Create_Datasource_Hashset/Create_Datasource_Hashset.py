# This python autopsy module create a hashset from a datasource where the hashs have already be computed
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> gmail [dot] com]
#
# No one is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, unless permission is 
# granted from the plugin original author (Mark McKinnon).
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Remove custom Artifacts and attributes.
# February 2017
# 
# Comments 
#   Version 1.0 - Initial version - Feb 2017
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
class Create_DS_HashsetIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Create_Datasource_Hashset"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Create A Hashset Based On the Hashs In A Datasource"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return Create_DS_HashsetIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class Create_DS_HashsetIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(Create_DS_HashsetIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.list_box_entry = []
        self.delete_all_artifacts = False
        self.delete_all_attributes = False

    # Where any setup and configuration is done
    def startUp(self, context):
        self.context = context
        pass

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        imageFiles = dataSource.getPaths()
        imageFile = os.path.basename(imageFiles[0])
        exportFile = os.path.join(Case.getCurrentCase().getExportDirectory(), str(imageFile) + "_hashset.txt")
        #self.log(Level.INFO, "create Directory " + moduleDirectory)

        
        sql_statement = 'select name, md5 from tsk_files where md5 <> "";'
        skCase = Case.getCurrentCase().getSleuthkitCase()
        dbquery = skCase.executeQuery(sql_statement)
        resultSet = dbquery.getResultSet()
        
        with open(exportFile, 'w') as f:   
            while resultSet.next():
                f.write(resultSet.getString("md5") + "\t" + resultSet.getString("name") + "\n")
        
        dbquery.close()
           
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Create_DS_Hashset", " Hashset Create For Datasource " + imageFile )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		


