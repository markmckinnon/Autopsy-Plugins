# This python autopsy module will read a CSV file of Latitude Longitude values
# and create points on a map.
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> Gmail [dot] com]
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

# 
# Comments 
#   Version 1.0 - Initial version - Aug 2025
# 

import jarray
import inspect
import os
import csv
from geopy.geocoders import Nominatim

from java.net import URL
from java.io import BufferedReader, InputStreamReader
import json

from java.lang import Class
from java.lang import System
from java.util.logging import Level
from java.io import File
from java.util import ArrayList
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import Blackboard
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskCoreException
from org.sleuthkit.datamodel import TskDataException
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
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class LatLongIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "LatLong Mapping"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses CSV Lat Long File"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def hasIngestJobSettingsPanel(self):
        return False

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return LatLongIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class LatLongIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(LatLongIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)


    def __init__(self, settings):
        self.context = None
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")

    def startUp(self, context):
        self.context = context

        pass

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = skCase.getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        
        file_name = dataSource.getName()
        lat_long_files = fileManager.findFiles(dataSource, file_name, "")
        numFiles = len(lat_long_files)

        # Read CSV File and Import into Autopsy
        moduleName = "LatLong Mapping"

        for file in lat_long_files:
            if file.getSize() == 0:
               continue            
            heading_read = False
            self.log(Level.INFO, "File to Process is " + file.getLocalAbsPath())
            with open(file.getLocalAbsPath(), 'rU') as csvfile:
                csvreader = csv.reader(csvfile, delimiter=',', quotechar='|')
                for row in csvreader:
                    if not heading_read:
                        heading_read = True
                    else:
                        try:
                            attributes = ArrayList()
                            latitude = row[0]
                            longitude = row[1]
                            location_name = " "
                            
                            geolocator = Nominatim(user_agent="Autopsy_FS")
                            try:
                                location = geolocator.reverse((latitude, longitude))
                                location_name = location.address
                            except:
                                self.log(Level.INFO, "Timeout error after 1st attempt")
                                for i in range(10):
                                    try:
                                        location = geolocator.reverse((latitude, longitude))
                                        location_name = location.address
                                        break
                                    except GeocoderTimedOut:
                                         self.log(Level.INFO, "Timeout error after 10 retries")

                            attributes.add(BlackboardAttribute(
                                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LATITUDE.getTypeID(), moduleName, float(latitude)))
                            attributes.add(BlackboardAttribute(
                                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE.getTypeID(), moduleName, float(longitude)))
                            attributes.add(BlackboardAttribute(
                                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCATION.getTypeID(), moduleName, location_name))

                            art = file.newDataArtifact(BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_BOOKMARK), attributes)#

                            blackboard.postArtifact(art, moduleName, self.context.getJobId())

                        except Blackboard.BlackboardException as e:
                            self.log(Level.SEVERE, "Error posting GPS bookmark artifact for " +
                                     file.getUniquePath() + " (objID = " + str(file.getId()) + "):" + e.getMessage())
                        except TskCoreException as e:
                            self.log(Level.SEVERE, "Error creating GPS bookmark artifact for " +
                                     file.getUniquePath() + " (objID = " + str(file.getId()) + "):" + e.getMessage())

        # Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "LatLong", " Lat Long points generated on Map " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
