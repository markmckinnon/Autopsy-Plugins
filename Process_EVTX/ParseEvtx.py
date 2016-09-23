# This python autopsy module will export the Windows Event Logs and then call
# the command line version of the Export_EVTX program.  A sqlite database that
# contains the Event Log information is created then imported into the extracted
# view section of Autopsy.
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> Davenport [dot] edu]
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

# Event Log module to parse the Windows Event Logs.
# March 2016
# 
# Comments 
#   Version 1.0 - Initial version - March 2016
#   Version 1.1 - Add custom artifact/attributes - August 28th 2016
# 

import jarray
import inspect
import os
import subprocess

from javax.swing import JCheckBox
from javax.swing import JList
from javax.swing import JTextArea
from javax.swing import BoxLayout
from java.awt import GridLayout
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JScrollPane
from javax.swing import JComponent
from java.awt.event import KeyListener


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
class ParseEvtxDbIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "ParseEvtx"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses EVTX files"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return Process_EVTX1WithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    # TODO: Update class names to ones that you create below
    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, Process_EVTX1WithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return Process_EVTX1WithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseEvtxDbIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ParseEvtxDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseEvtxDbIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_Events = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_EVTX.exe")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("EXE was not found in module folder")
        
        if self.local_settings.getFlag():
            self.List_Of_Events.append('ALL')
            #self.logger.logp(Level.INFO, Process_EVTX1WithUI.__name__, "startUp", "All Events CHecked")
        else:
            #self.logger.logp(Level.INFO, Process_EVTX1WithUI.__name__, "startUp", "No Boxes Checked")
            if self.local_settings.getFlag1():
                self.List_Of_Events.append('Application.Evtx')
            if self.local_settings.getFlag2():
                self.List_Of_Events.append('Security.Evtx')
            if self.local_settings.getFlag3():
                self.List_Of_Events.append('System.Evtx')
            if self.local_settings.getFlag4():
                self.List_Of_Events.append('Other')
                Event_List = self.local_settings.getArea().split()
                for evt in Event_List:
                   self.List_Of_Events.append(str(evt))
        
        #self.logger.logp(Level.INFO, Process_EVTX1WithUI.__name__, "startUp", str(self.List_Of_Events))
        self.log(Level.INFO, str(self.List_Of_Events))
		
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # Check to see if the artifacts exist and if not then create it, also check to see if the attributes
		# exist and if not then create them
        skCase = Case.getCurrentCase().getSleuthkitCase();
        skCase_Tran = skCase.beginTransaction()
        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_evtx = skCase.addArtifactType( "TSK_EVTX_LOGS", "Windows Event Logs")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_evtx = skCase.getArtifactTypeID("TSK_EVTX_LOGS")
 
        try:
            attID_ev_fn = skCase.addArtifactAttributeType("TSK_EVTX_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Log File Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Event Log File Name. ==> ")
        try:
            attID_ev_rc = skCase.addArtifactAttributeType("TSK_EVTX_RECOVERED_RECORD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Recovered Record")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Recovered Record. ==> ")
        try:
            attID_ev_cn = skCase.addArtifactAttributeType("TSK_EVTX_COMPUTER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Computer Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Computer Name. ==> ")
        try:
            attID_ev_ei = skCase.addArtifactAttributeType("TSK_EVTX_EVENT_IDENTIFIER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Identiifier")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Event Log File Name. ==> ")
        try:
            attID_ev_eiq = skCase.addArtifactAttributeType("TSK_EVTX_EVENT_IDENTIFIER_QUALIFERS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Identifier Qualifiers")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Event Identifier Qualifiers. ==> ")
        try:
            attID_ev_el = skCase.addArtifactAttributeType("TSK_EVTX_EVENT_LEVEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Level")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Event Level. ==> ")
        try:
            attID_ev_oif = skCase.addArtifactAttributeType("TSK_EVTX_OFFSET_IN_FILE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Offset In File")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Event Offset In File. ==> ")
        try:
            attID_ev_id = skCase.addArtifactAttributeType("TSK_EVTX_IDENTIFIER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Identifier")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Identifier. ==> ")
        try:
            attID_ev_sn = skCase.addArtifactAttributeType("TSK_EVTX_SOURCE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Source Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Source Name. ==> ")
        try:
            attID_ev_usi = skCase.addArtifactAttributeType("TSK_EVTX_USER_SECURITY_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User Security ID")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, User Security ID. ==> ")
        try:
            attID_ev_et = skCase.addArtifactAttributeType("TSK_EVTX_EVENT_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Time")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Event Time. ==> ")
        try:
            attID_ev_ete = skCase.addArtifactAttributeType("TSK_EVTX_EVENT_TIME_EPOCH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Time Epoch")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Identifier. ==> ")
        try:
            attID_ev_dt = skCase.addArtifactAttributeType("TSK_EVTX_EVENT_DETAIL_TEXT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Detail")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Event Detail. ==> ")

        #self.log(Level.INFO, "Get Artifacts after they were created.")
        # Get the new artifacts and attributes that were just created
        artID_evtx = skCase.getArtifactTypeID("TSK_EVTX_LOGS")
        artID_evtx_evt = skCase.getArtifactType("TSK_EVTX_LOGS")
        attID_ev_fn = skCase.getAttributeType("TSK_EVTX_FILE_NAME")
        attID_ev_rc = skCase.getAttributeType("TSK_EVTX_RECOVERED_RECORD")			 
        attID_ev_cn = skCase.getAttributeType("TSK_EVTX_COMPUTER_NAME")			 
        attID_ev_ei = skCase.getAttributeType("TSK_EVTX_EVENT_IDENTIFIER")
        attID_ev_eiq = skCase.getAttributeType("TSK_EVTX_EVENT_IDENTIFIER_QUALIFERS")
        attID_ev_el = skCase.getAttributeType("TSK_EVTX_EVENT_LEVEL")
        attID_ev_oif = skCase.getAttributeType("TSK_EVTX_OFFSET_IN_FILE")
        attID_ev_id = skCase.getAttributeType("TSK_EVTX_IDENTIFIER")
        attID_ev_sn = skCase.getAttributeType("TSK_EVTX_SOURCE_NAME")
        attID_ev_usi = skCase.getAttributeType("TSK_EVTX_USER_SECURITY_ID")
        attID_ev_et = skCase.getAttributeType("TSK_EVTX_EVENT_TIME")
        attID_ev_ete = skCase.getAttributeType("TSK_EVTX_EVENT_TIME_EPOCH")
        attID_ev_dt = skCase.getAttributeType("TSK_EVTX_EVENT_DETAIL_TEXT")
        
        #self.log(Level.INFO, "Artifact id for TSK_PREFETCH ==> " + str(artID_pf))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_FILE_NAME ==> " + str(attID_ev_fn))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_RECOVERED_RECORD ==> " + str(attID_ev_rc))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_COMPUTER_NAME ==> " + str(attID_ev_cn))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_EVENT_IDENTIFIER ==> " + str(attID_ev_ei))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_EVENT_IDENTIFIER_QUALIFERS ==> " + str(attID_ev_eiq))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_EVENT_LEVEL ==> " + str(attID_ev_el))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_OFFSET_IN_FILE ==> " + str(attID_ev_oif))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_IDENTIFIER ==> " + str(attID_ev_id))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_SOURCE_NAME ==> " + str(attID_ev_sn))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_USER_SECURITY_ID ==> " + str(attID_ev_usi))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_EVENT_TIME ==> " + str(attID_ev_et))
        # self.log(Level.INFO, "Attribute id for TSK_EVTX_EVENT_TIME_EPOCH ==> " + str(attID_ev_ete))
        # self.log(Level.INFO, "Attribute id for TSK_EVXT_EVENT_DETAIL_TEXT ==> " + str(attID_ev_dt))

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Find the Windows Event Log Files
        files = []		
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        if self.List_Of_Events[0] == 'ALL':
           files = fileManager.findFiles(dataSource, "%.evtx")
        else:
           for eventlog in self.List_Of_Events:
               file_name = fileManager.findFiles(dataSource, eventlog)
               files.extend(file_name)
               #self.log(Level.INFO, "found " + str(file_name) + " files")
        #self.log(Level.INFO, "found " + str(files) + " files")

        
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
		
        # Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\EventLogs")
        except:
		    self.log(Level.INFO, "Event Log Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\EventLogs", file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        

        # Example has only a Windows EXE, so bail if we aren't on Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
            return IngestModule.ProcessResult.OK

        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on data source parm 1 ==> " + Temp_Dir + "  Parm 2 ==> " + Temp_Dir + "\EventLogs.db3")
        subprocess.Popen([self.path_to_exe, Temp_Dir + "\EventLogs", Temp_Dir + "\EventLogs.db3"]).communicate()[0]   
			
        # Set the database to be read to the one created by the Event_EVTX program
        lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "EventLogs.db3")
        self.log(Level.INFO, "Path to the Eventlogs database file created ==> " + lclDbPath)
                        
        # Open the DB using JDBC
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
            
        files = []
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        if self.List_Of_Events[0] == 'ALL':
           files = fileManager.findFiles(dataSource, "%.evtx")
        else:
           for eventlog in self.List_Of_Events:
               file_name = fileManager.findFiles(dataSource, eventlog)
               files.extend(file_name)
               #self.log(Level.INFO, "found " + str(file_name) + " files")
        #self.log(Level.INFO, "found " + str(files) + " files")
            
        for file in files:
            file_name = file.getName()
            self.log(Level.INFO, "File To process in SQL " + file_name + "  <<=====")
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = "SELECT File_Name, Recovered_Record, Computer_name, Event_Identifier, " + \
                                " Event_Identifier_Qualifiers, Event_Level, Event_offset, Identifier, " + \
                                " Event_source_Name, Event_User_Security_Identifier, Event_Time, " + \
                                " Event_Time_Epoch, Event_Detail_Text FROM Event_Logs where upper(File_Name) = upper('" + file_name + "')"
                #self.log(Level.INFO, "SQL Statement " + SQL_Statement + "  <<=====")
            	resultSet = stmt.executeQuery(SQL_Statement)
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for EventLogs table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    #File_Name  = resultSet.getString("File_Name")
                    #Recovered_Record = resultSet.getString("Recovered_Record")
                    Computer_Name = resultSet.getString("Computer_Name")
                    Event_Identifier = resultSet.getString("Event_Identifier")
                    #Event_Identifier_Qualifiers = resultSet.getString("Event_Identifier_Qualifiers")
                    Event_Level = resultSet.getString("Event_Level")
                    #Event_Offset = resultSet.getString("Event_Offset")
                    #Identifier = resultSet.getString("Identifier")
                    Event_Source_Name = resultSet.getString("Event_Source_Name")
                    Event_User_Security_Identifier = resultSet.getString("Event_User_Security_Identifier")
                    Event_Time = resultSet.getString("Event_Time")
                    #Event_Time_Epoch = resultSet.getString("Event_Time_Epoch")
                    Event_Detail_Text = resultSet.getString("Event_Detail_Text")
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
        
                # Make an artifact on the blackboard, TSK_PROG_RUN and give it attributes for each of the fields
                # Make artifact for TSK_EVTX_LOGS
                art = file.newArtifact(artID_evtx)

                art.addAttributes(((BlackboardAttribute(attID_ev_cn, ParseEvtxDbIngestModuleFactory.moduleName, Computer_Name)), \
                                   (BlackboardAttribute(attID_ev_ei, ParseEvtxDbIngestModuleFactory.moduleName, Event_Identifier)), \
                                   (BlackboardAttribute(attID_ev_el, ParseEvtxDbIngestModuleFactory.moduleName, Event_Level)), \
                                   (BlackboardAttribute(attID_ev_sn, ParseEvtxDbIngestModuleFactory.moduleName, Event_Source_Name)), \
                                   (BlackboardAttribute(attID_ev_usi, ParseEvtxDbIngestModuleFactory.moduleName, Event_User_Security_Identifier)), \
                                   (BlackboardAttribute(attID_ev_et, ParseEvtxDbIngestModuleFactory.moduleName, Event_Time)), \
                                   (BlackboardAttribute(attID_ev_dt, ParseEvtxDbIngestModuleFactory.moduleName, Event_Detail_Text))))
                # These attributes may also be added in the future
                #art.addAttribute(BlackboardAttribute(attID_ev_fn, ParseEvtxDbIngestModuleFactory.moduleName, File_Name))
                #art.addAttribute(BlackboardAttribute(attID_ev_rc, ParseEvtxDbIngestModuleFactory.moduleName, Recovered_Record))
                #art.addAttribute(BlackboardAttribute(attID_ev_eiq, ParseEvtxDbIngestModuleFactory.moduleName, Event_Identifier_Qualifiers))
                #art.addAttribute(BlackboardAttribute(attID_ev_oif, ParseEvtxDbIngestModuleFactory.moduleName, Event_Offset))
                #art.addAttribute(BlackboardAttribute(attID_ev_id, ParseEvtxDbIngestModuleFactory.moduleName, Identifier))
                #art.addAttribute(BlackboardAttribute(attID_ev_ete, ParseEvtxDbIngestModuleFactory.moduleName, Event_Time_Epoch))
			
        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(ParseEvtxDbIngestModuleFactory.moduleName, artID_evtx_evt, None))
                
        # Clean up
        stmt.close()
        dbConn.close()
        os.remove(lclDbPath)
			
		#Clean up EventLog directory and files
        for file in files:
            try:
			    os.remove(Temp_Dir + "\\" + file.getName())
            except:
			    self.log(Level.INFO, "removal of Event Log file failed " + Temp_Dir + "\\" + file.getName())
        try:
             os.rmdir(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of Event Logs directory failed " + Temp_Dir)
 
        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(ParseEvtxDbIngestModuleFactory.moduleName, artID_evtx_evt, None))
             
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "ParseEvtx", " Event Logs have been parsed " )
        IngestServices.getInstance().postMessage(message)

        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(ParseEvtxDbIngestModuleFactory.moduleName, artID_evtx_evt, None))
        
        return IngestModule.ProcessResult.OK
		
# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class Process_EVTX1WithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.flag = False
        self.flag1 = False
        self.flag2 = False
        self.flag3 = False
        self.flag4 = False
        self.area = ""

    def getVersionNumber(self):
        return serialVersionUID

    # TODO: Define getters and settings for data you want to store from UI
    def getFlag(self):
        return self.flag

    def setFlag(self, flag):
        self.flag = flag

    def getFlag1(self):
        return self.flag1

    def setFlag1(self, flag1):
        self.flag1 = flag1

    def getFlag2(self):
        return self.flag2

    def setFlag2(self, flag2):
        self.flag2 = flag2

    def getFlag3(self):
        return self.flag3

    def setFlag3(self, flag3):
        self.flag3 = flag3

    def getFlag4(self):
        return self.flag4

    def setFlag4(self, flag4):
        self.flag4 = flag4

    def getArea(self):
        return self.area

    def setArea(self, area):
        self.area = area

# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class Process_EVTX1WithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
    
    # TODO: Update this for your UI
    def checkBoxEvent(self, event):
        if self.checkbox.isSelected():
            self.local_settings.setFlag(True)
        else:
            self.local_settings.setFlag(False)
        if self.checkbox1.isSelected():
            self.local_settings.setFlag1(True)
        else:
            self.local_settings.setFlag1(False)
        if self.checkbox2.isSelected():
            self.local_settings.setFlag2(True)
        else:
            self.local_settings.setFlag2(False)
        if self.checkbox3.isSelected():
            self.local_settings.setFlag3(True)
        else:
            self.local_settings.setFlag3(False)
        if self.checkbox4.isSelected():
            self.local_settings.setFlag4(True)
            self.local_settings.setArea(self.area.getText());
        else:
            self.local_settings.setFlag4(False)

    def keyPressed(self, event):
        self.local_settings.setArea(self.area.getText());

    # TODO: Update this for your UI
    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        #self.setLayout(GridLayout(0,1))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.panel1 = JPanel()
        self.panel1.setLayout(BoxLayout(self.panel1, BoxLayout.Y_AXIS))
        self.panel1.setAlignmentY(JComponent.LEFT_ALIGNMENT)
        self.checkbox = JCheckBox("All Logs", actionPerformed=self.checkBoxEvent)
        self.checkbox1 = JCheckBox("Application.Evtx", actionPerformed=self.checkBoxEvent)
        self.checkbox2 = JCheckBox("Security.EVTX", actionPerformed=self.checkBoxEvent)
        self.checkbox3 = JCheckBox("System.EVTX", actionPerformed=self.checkBoxEvent)
        self.checkbox4 = JCheckBox("Other - Input in text area below then check this box", actionPerformed=self.checkBoxEvent)
        self.panel1.add(self.checkbox)
        self.panel1.add(self.checkbox1)
        self.panel1.add(self.checkbox2)
        self.panel1.add(self.checkbox3)
        self.panel1.add(self.checkbox4)
        self.add(self.panel1)
		
        self.area = JTextArea(5,25)
        #self.area.addKeyListener(self)
        self.area.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))
        self.pane = JScrollPane()
        self.pane.getViewport().add(self.area)
        #self.pane.addKeyListener(self)
        #self.add(self.area)
        self.add(self.pane)
		
    # TODO: Update this for your UI
    def customizeComponents(self):
        self.checkbox.setSelected(self.local_settings.getFlag())
        self.checkbox1.setSelected(self.local_settings.getFlag1())
        self.checkbox2.setSelected(self.local_settings.getFlag2())
        self.checkbox3.setSelected(self.local_settings.getFlag3())
        self.checkbox4.setSelected(self.local_settings.getFlag4())

    # Return the settings used
    def getSettings(self):
        return self.local_settings

 