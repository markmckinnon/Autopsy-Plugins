# This python autopsy module will pull all the indexed content from solr and 
# attempt to make a word list that can be used to crack passwords
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

# Wordlist to export solr index.
# June 2020
# 
# Comments 
#   Version 1.0 - Initial version - June 2020
#           1.1 - Fixed mispelling in description and use getName instead of getNumber since caseNumber can be blank.

import jarray
import inspect
import os
from time import strptime, mktime 
import json
import shutil
import urllib
import json
import hashlib
import xml.etree.ElementTree as ET
import re


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
from org.sleuthkit.autopsy.keywordsearch import Server
from org.sleuthkit.autopsy.keywordsearchservice import KeywordSearchService
from org.sleuthkit.autopsy.keywordsearch import KeywordSearch



# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class WordlistIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Wordlist"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Create Wordlist From Solr"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return WordlistIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class WordlistIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(WordlistIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.INFO, "Starting of plugin")
        self.host       = "localhost"
        self.port       = "23232"
        self.qt         = "select"
        self.q          = "q=text:*"
        self.fl         = "fl=text"
        self.wt         = "wt=json"

    def startUp(self, context):
        self.context = context
        pass
        
    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        coreName = self.findCoreName(Case.getCurrentCase().getName())
        
        self.log(Level.INFO, "Core name is ==> " + str(coreName))
        
        if (coreName is not None):
        # get current case and the store.vol abstract file information
            #skCase = Case.getCurrentCase().getSleuthkitCase();
            #fileManager = Case.getCurrentCase().getServices().getFileManager()

            # Get the exported file name will have case number in the name and be in the export directory
            exportFile = os.path.join(Case.getCurrentCase().getExportDirectory(), Case.getCurrentCase().getName() + "_wordlist.txt")
            exportErrorFile = os.path.join(Case.getCurrentCase().getExportDirectory(), Case.getCurrentCase().getName() + "_wordlist_Errors.txt")
            
            url        = 'http://' + self.host + ':' + self.port + '/solr/' + coreName + '/' + self.qt + '?'
            start      = "start=" + str(0)
            rows       = "rows=" + str(10)
            params     = [ self.q, start, rows, self.wt ]
            p          = "&".join(params)


            timesToRun = self.numberOfEntries(url, p)            
            self.log(Level.INFO, "Times to Run ==> " + str(timesToRun))
            
            wordHashDict = {}

            with open(exportFile, "w") as wordlist:
                with open(exportErrorFile, 'w') as wordlistError:
                    for i in range(0, timesToRun + 1, 1):

                        if self.context.isJobCancelled():
                            return IngestModule.ProcessResult.OK

                        startPage = (i * 1000)
                        start = "start=" + str(startPage)
                        rows = "rows=" + str(1000)
                        params = [self.q, start, rows, self.wt]
                        p = "&".join(params)
                        
                        self.log(Level.INFO, "Pageset to process ==> " + str(startPage))

                        connection = urllib.urlopen(url+p)
                        response   = json.load(connection)
                        connection.close()

                        docsFound = response['response']['docs']

                        for docFound in docsFound:
                            try:
                                if 'text' in docFound:
                                    if (len(docFound['text']) > 1):
                                        docList = docFound['text']
                                        wordListSplit = re.split(' |\t', docList[1])
                                        for wordl in wordListSplit:
                                            md5Hash = hashlib.md5(wordl.encode('utf-8').strip()).hexdigest()
                                            if md5Hash in wordHashDict:
                                                continue
                                            else:
                                                wordHashDict[md5Hash] = None
                                                wordlist.write(wordl.encode('utf-8').strip() + "\n")
                                    # use whole file name
                                    md5Hash = hashlib.md5(docList[0]).hexdigest()
                                    if md5Hash in wordHashDict:
                                        continue
                                    else:
                                        wordHashDict[md5Hash] = None
                                        wordlist.write(docList[0] + "\n")
                                    # Split file name and extension and add them in seperately
                                    fileParts = docList[0].split(".")
                                    for wordl in fileParts:
                                        md5Hash = hashlib.md5(wordl.encode('utf-8').strip()).hexdigest()
                                        if md5Hash in wordHashDict:
                                            continue
                                        else:
                                            wordHashDict[md5Hash] = None
                                            wordlist.write(wordl.encode('utf-8').strip() + "\n")
                                    
                            except Exception as e:
                                wordlistError.write("Error ==> " + str(e) + " ==> " + str(docFound['text']) + "\n")


        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Wordlist", " Wordlidt has been created " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
        
    def findCoreName(self, caseName):
    
        connection = urllib.urlopen("http://localhost:23232/solr/admin/cores?action=status")
        root = ET.fromstring(connection.read())
        for child in root.iter('*'):
            if caseName in str(child.attrib.values()):
                return str(child.attrib.values()[0])
        return None

    def numberOfEntries(self, url, p):
    
        connection = urllib.urlopen(url+p)
        response   = json.load(connection)
        connection.close()

        numFound = response['response']['numFound']

        #self.log(Level.INFO, "Number of Entries ==> " + str(numFound))
        return (numFound / 1000 + 1)

    
    