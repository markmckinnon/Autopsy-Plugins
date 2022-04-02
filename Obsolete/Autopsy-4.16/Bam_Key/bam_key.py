# This python autopsy module will Extract the system and sam registry hive.
#  It will parse out the BAM key and attribute users to it then bring it
#  into Autopsy
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

# bam_key.py.
# April 2019
# 
# Comments 
#   Version 1.0 - Initial version - April 2019
#   Version 1.1 - Remove external program dependency and use internal rejistry
# 

#import jarray
import inspect
import os
import shutil
import struct
import binascii
import codecs

from com.williballenthin.rejistry import RegistryHiveFile
from com.williballenthin.rejistry import RegistryKey
from com.williballenthin.rejistry import RegistryParseException
from com.williballenthin.rejistry import RegistryValue
from java.io import File
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
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
class BamKeyIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Bam Key Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Extract BAM Registry Information"
    
    def getModuleVersionNumber(self):
        return "1.1"
    
    def hasIngestJobSettingsPanel(self):
        return False

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return BamKeyIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class BamKeyIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(BamKeyIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
 
    # Where any setup and configuration is done
    def startUp(self, context):
        self.context = context
        # Hive Keys to parse, use / as it is easier to parse out then \\
        self.registrySAMKey = 'SAM/Domains/Account/Users'
        self.registryBamKey = 'controlset001/services/bam/UserSettings'
        self.registryBamKeyNew = 'controlset001/services/bam/State/UserSettings'

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Hive files to extract        
        filesToExtract = ("SAM", "SYSTEM")
        
        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Create BAM directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        temp_dir = os.path.join(Temp_Dir, "bam")
        self.log(Level.INFO, "create Directory " + temp_dir)
        try:
		    os.mkdir(temp_dir)
        except:
		    self.log(Level.INFO, "bam Directory already exists " + temp_dir)

        # Setup variables to use to store information
        systemHiveFile = []
        userRids = {}
        bamRecord = []
        
        for fileName in filesToExtract:
            files = fileManager.findFiles(dataSource, fileName, "Windows/System32/Config")
            numFiles = len(files)

            for file in files:
            
                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                # Check path to only get the hive files in the config directory and no others
                if file.getParentPath().upper() == '/WINDOWS/SYSTEM32/CONFIG/':    
                    # Save the DB locally in the temp folder. use file id as name to reduce collisions
                    filePath = os.path.join(temp_dir, file.getName())
                    ContentUtils.writeToFile(file, File(filePath))
                    # Save SYSTEM Hive abstract file information to use later
                    if file.getName() == 'SYSTEM':
                       systemHiveFile = file
                       bamRecord = self.processSYSTEMHive(filePath)
                    elif file.getName() == 'SAM':
                        # Get information from the SAM file returns dictionary with key of rid and value of user name
                        userRids = self.processSAMHive(filePath)
        
        # Setup Artifact
        try:
            self.log(Level.INFO, "Begin Create New Artifacts")
            artID_ls = skCase.addArtifactType( "TSK_BAM_KEY", "BAM Registry Key")
        except:		
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            
        artifactName = "TSK_BAM_KEY"
        artId = skCase.getArtifactTypeID(artifactName)

        moduleName = BamKeyIngestModuleFactory.moduleName
        
        # Attributes to use TSK_USER_NAME, TSK_PROG_NAME, TSK_DATETIME
        for bamRec in bamRecord:
            attributes = ArrayList()
            art = systemHiveFile.newArtifact(artId)
            
            self.log(Level.INFO, "BamRec ==> " + str(bamRec))
            
            if bamRec[0] in userRids.keys():
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), moduleName, userRids[bamRec[0]]))
            else:
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), moduleName, bamRec[0]))
            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), moduleName, bamRec[1]))
            attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), moduleName, int(bamRec[2])))
            art.addAttributes(attributes)

            # index the artifact for keyword search
            try:
                blackboard.indexArtifact(artChat)
            except:
                self._logger.log(Level.WARNING, "Error indexing artifact " + art.getDisplayName())
        
		#Clean up prefetch directory and files
        try:
             shutil.rmtree(temp_dir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + temp_dir)
 
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "BamKey", " BamKey Files Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                

    def processSYSTEMHive(self, systemHive):
    
        bamRecord = []
        systemRegFile = RegistryHiveFile(File(systemHive))
        try:
            currentKey = self.findRegistryKey(systemRegFile, self.registryBamKey)
        except:
            self.log(Level.INFO, "Unable to find old Bam key, trying new location")
            currentKey = self.findRegistryKey(systemRegFile, self.registryBamKeyNew)
        bamKey = currentKey.getSubkeyList()
        for sk in bamKey:
            if len(sk.getValueList()) > 0:
                registryKey = sk.getName()
                skValues = sk.getValueList()
                for skValue in skValues:
                    if skValue.getName() == 'SequenceNumber' or skValue.getName() == 'Version':
                        pass
                    else:
                        indRecord = []
                        value = skValue.getValue()
                        binData = self.getRawData(value.getAsRawData())
                        msTime = struct.unpack('<qqq', binData)[0]
                        linuxTime = int(str(msTime)[0:11]) - 11644473600
                        uId = registryKey[registryKey.rfind("-")+1:]
                        indRecord.append(uId)
                        indRecord.append(str(skValue.getName()))
                        indRecord.append(str(linuxTime))                  
                        bamRecord.append(indRecord)
        return bamRecord


    def processSAMHive(self, samHive):
    
        userId = {}
        samRegFile = RegistryHiveFile(File(samHive))
        currentKey = self.findRegistryKey(samRegFile, self.registrySAMKey)
        samKey = currentKey.getSubkeyList()   
        for sk in samKey:
            registryKey = sk.getName()
            skValues = sk.getValueList()
            if len(skValues) > 0:
                for skVal in skValues:
                    if skVal.getName() == 'V':
                        value = skVal.getValue()
                        hexArray = self.getRawData(value.getAsRawData())
                        pos1 = int(str(struct.unpack_from('<l', hexArray[4:])[0]))
                        pos3 = int(str(struct.unpack_from('<l', hexArray[12:])[0])) + 204 
                        pos4 = int(str(struct.unpack_from('<l', hexArray[16:])[0]))
                        pos6 = int(str(struct.unpack_from('<l', hexArray[24:])[0])) + 204
                        pos7 = int(str(struct.unpack_from('<l', hexArray[28:])[0]))
                        pos9 = int(str(struct.unpack_from('<l', hexArray[36:])[0])) + 204
                        pos10 = int(str(struct.unpack_from('<l', hexArray[40:])[0]))
                        fmtStringName = "<" + str(pos4) + "s"		  
                        fmtStringFullname = ">" + str(pos7) + "s"
                        fmtStringComment = ">" + str(pos10) + "s"
                        userName = struct.unpack_from(fmtStringName, hexArray[pos3:])[0]
                        fullName = struct.unpack_from(fmtStringFullname, hexArray[pos6:])[0]
                        comment = struct.unpack_from(fmtStringComment, hexArray[pos9:])[0]
                        userName = self.utf16decode(userName)
                        userId[str(int(registryKey, 16))] = userName

        return userId

    def getRawData(self, rawData):
    
        hexArray = ""
        arrayLength = rawData.remaining()
        for x in range(0, arrayLength):
            binByte = rawData.get()
            # Have to check if this is a negative number or not.  Byte will be returned -127 to 127 instead of 0 to 255
            if binByte < 0:
                binByte = 256 + binByte
            hexArray = hexArray + chr(binByte)
        return hexArray
    
    def findRegistryKey(self, registryHiveFile, registryKey):
    
        rootKey = registryHiveFile.getRoot()
        regKeyList = registryKey.split('/')
        currentKey = rootKey
        for key in regKeyList:
            self.log(Level.INFO, "Key value is ==> " + key)
            self.log(Level.INFO, "Current Key is ==> " + str(currentKey))
            currentKey = currentKey.getSubkey(key) 
        return currentKey   

    def utf16decode(self, bytes):

        ## Take the UTF-16LE encoded strings as bytes and convert to a UTF-8 string. Jython-compatible.
        ## code taken from Sam Koffman that he created for his plugin Autopsy-MSOT
        ## https://github.com/MadScientistAssociation/Autopsy-MSOT/blob/5f31ce521f4df3839fc825d00e82d9a6e97dfcff/lib/misc_functions_aut.py

        bytes = binascii.hexlify(bytes)
        bytes = [bytes[i:i+2] for i in range(0, len(bytes), 2)]
        bytes = (''.join(filter(lambda a: a !='00', bytes)))
        bytes = codecs.decode(bytes, 'hex')
        return(bytes)
        


