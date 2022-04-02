# Autopsy-Plugins

This is a repository of Autopsy Python Plugins.  You can download all of them and place them in the python plugin directory.  All the plugins will recompile on execution.

- [Autopsy-Plugins](#autopsy-plugins)
  - [Plugin Overview](#plugin-overview)
    - [AD1_Extractor](#ad1_extractor)
    - [Amazon Echosystem Parser](#amazon-echosystem-parser)
    - [Atomic Wallet](#atomic-wallet)
    - [CCM Recently Used Apps](#ccm-recently-used-apps)
    - [ClamAV Hashsets](#clamav-hashsets)
    - [Create Data Source Hashset](#create-data-source-hashset)
    - [Create Preview Data Container](#create-preview-data-container)
    - [Cuckoo](#cuckoo)
    - [DJI Phantom Drone Parser](#dji-phantom-drone-parser)
    - [Parse File History](#parse-file-history)
    - [Gui Test](#gui-test)
    - [Gui Test With Settings](#gui-test-with-settings)
    - [LevelDB Parser](#leveldb-parser)
    - [MacFSEvents](#macfsevents)
    - [MacOSX Recent](#macosx-recent)
    - [MacOSX Safari](#macosx-safari)
    - [Mac Mail Parser](#mac-mail-parser)
    - [Mass Export By Extension](#mass-export-by-extension)
    - [Obsolete](#obsolete)
    - [Parse PList](#parse-plist)
    - [Parse QNX Image](#parse-qnx-image)
    - [Parse SQLite DBs](#parse-sqlite-dbs)
    - [Parse SQLite DB Del Records](#parse-sqlite-db-del-records)
    - [Parse Usnj](#parse-usnj)
    - [Plaso (2 Plugins in this directory)](#plaso-2-plugins-in-this-directory)
    - [Process Activities Cache](#process-activities-cache)
    - [Parse Amache](#parse-amache)
    - [Process Appx Programs](#process-appx-programs)
    - [Process Appxreg Programs](#process-appxreg-programs)
    - [Parse EVTX](#parse-evtx)
    - [Parse EVTX by Event ID](#parse-evtx-by-event-id)
    - [Process Extract VSS](#process-extract-vss)
    - [Process Facebook Chats](#process-facebook-chats)
    - [Process Teracopy](#process-teracopy)
    - [Process Windows Mail](#process-windows-mail)
    - [Remove Artifacts](#remove-artifacts)
    - [Parse RingCentral](#parse-ringcentral)
    - [Shimache Parser](#shimache-parser)
    - [Spotlight Parser](#spotlight-parser)
    - [Thumbcache Parser](#thumbcache-parser)
    - [Thumbs Parser](#thumbs-parser)
    - [Timesketch](#timesketch)
    - [UAL Parser](#ual-parser)
    - [Volatility (3 plugins in this directory)](#volatility-3-plugins-in-this-directory)
    - [Webcache](#webcache)
    - [Windows Internals](#windows-internals)
  - [Linux Compatible Plugins](#linux-compatible-plugins)
  - [Need Help?](#need-help)

## Plugin Overview
Here is a brief overview of all of the plugins.

### AD1_Extractor
To-Do

### [Amazon Echosystem Parser](./Amazon_Echosystem_Parser/README.md)
Parse the databases from an Amazon Alexa image.

### Atomic Wallet
To-Do

### CCM Recently Used Apps
Parse the [WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) database for Recently used apps.
### ClamAV Hashsets
To-Do

### Create Data Source Hashset
Will create a file with the hashset of a data source that can then be pulled back into Autopsy as a hash set.

### Create Preview Data Container
Create VHD expandable volumen and mount it.  Then read SQLite database of file extensions that can be exported to it and export those files matching the file extensions.  Finally it will unmount the VHD so it can be added back into an autopsy case.

### Cuckoo
Check the status of a [Cuckoo](https://cuckoosandbox.org/) server and submit files to it.

### DJI Phantom Drone Parser
To-Do

### Parse File History
Export the Catalog1.edb file and then call the command line version of the Expor_FileHistory.  A sqlite database that contains the File History information is created and then imported into the extracted view section of Autopsy.

### [Gui Test](./Gui_Test/README.md)
Example of the different types of things you can do with the GUI portion of Autopsy Python Plugins.

### [Gui Test With Settings](./Gui_Test_With_Settings/README.md)
Example of the saving and retrieving of settings from the GUI of an Autopsy Python Plugin.

### LevelDB Parser
To-Do
### MacFSEvents
Export the .fsevents directory and run the FSEParser_v2.1.exe program against the exported data.  It will then import the SQLite database that was created from the program.
### MacOSX Recent
Export/Parse Mac recents.
### MacOSX Safari
Export/Parse Mac OSX safari.  A SQLite database that contains the Safari information is created and then imported into the extracted view section of Autopsy.
### Mac Mail Parser
To-Do

### Mass Export By Extension
To-Do

### Obsolete 
Here lies the plugins no longer maintained as they are now integrated into Autopsy main.
### Parse PList
Parse any plist and convert it to a SQLite database and then import the information into the extracted contant.

### Parse QNX Image
To-Do

### [Parse SQLite DBs](./Parse_SQLite_Databases/README.md)
Parse any SQLite files and import them into the extracted content section of Autopsy.

### [Parse SQLite DB Del Records](./Parse_SQLite_Del_Records/README.md)
Parse any SQLite databases and look for deleted records.  It will then create a SQLite database with the deleted records and then be imported into the extracted content section of Autopsy.

### Parse Usnj
Export the $UsnJrnl:$J and then call the command line version of parseusn program.  A SQLite database that contains the NTFS UsrJrnl information is created and imported into the extracted view section of Autopsy.

### Plaso (2 Plugins in this directory)
Execute plaso or import a plaso file.

### Process Activities Cache
Will process the activities cache from Windows 10

### Parse Amache
Export the Amache Registry and then call the command line version of Export_Amache program.  A SQLite database contains the Amache information is created then imported into the extracted content view of Autopsy.

### Process Appx Programs
Parse the SQLite database that has the Windows 10 Store/metro apps database.

### Process Appxreg Programs
Parse the registry to read the Windows 10 Store/metro apps.

### [Parse EVTX](./Process_EVTX/README.md)
Export the Windows Event Logs and then call the command line version of the Export_EVTX program.  A SQLite database that contains the Event Log information is created and imported into the extracted view section of Autopsy.

### Parse EVTX by Event ID
Export all the Windows Event Logs and thenc all the command line version of the Export_EVTX program.  A SQLite database that conains the Event Log information is created then imported into the extracted view section of Autopsy as a Table based on Event_Log_Id.  the user can then run the module again and extract user supplied events from the Evtx SQLite database.

### Process Extract VSS
Example of the different types of things you can do with Autopsy plugin?

### Process Facebook Chats
Parses the chats from facebook on a windows OS.

### Process Teracopy
Process the Teracopy database

### Process Windows Mail
Process Windows Mail store and added messages to communication manager.

### Remove Artifacts
Will remove custom artifacts and attributes from a case.  For developer use.

### Parse RingCentral
To-Do

### Shimache Parser
Export the System Registry Hive and then call the command line version of the shimache_parser program.  A SQLite database that contains the shimache information is created then imported into the extracted view section of Autopsy.

### Spotlight Parser
Parses the Spotlight data from the macos.

### Thumbcache Parser
Export all the thumbcache_*.db files in the image and then run the [thumbcache_viewer_cmd](https://github.com/thumbcacheviewer/thumbcacheviewer) program against them and export the embedded files to the ModuleOutput directory so that the files can then be added back into Autopsy.

### Thumbs Parser
Export all the thumbs.db files in the image and then run the [thumbs_viewer](https://github.com/thumbsviewer/thumbsviewer) program against them and export the embedded files to the ModuleOutput directory so that the files can then be added back into Autopsy.

### Timesketch
Export all date/time data to a Timesketch server

### UAL Parser
A parser based on [KStrike](https://github.com/brimorlabs/KStrike) to parse and process the [UAL](https://docs.microsoft.com/en-us/powershell/module/useraccesslogging/?view=windowsserver2022-ps) database and output the results to the main Autopsy window.

### Volatility (3 plugins in this directory)
Execute Volatility against a memory image.  It will ask the user for the directory where the Volatility executable reside then it will run volatility against the memory image using options the user specifies.

### Webcache
Module will export the WebcacheV01 file and then call the command line version of the Export_Esedb.  A SQLite database that contains the Webcache information is created then imported into the extracted view section of Autopsy.

### Windows Internals
Several windows plugins combined into one plugin.  You pick with checkboxes what you want it to do.

## Linux Compatible Plugins 
The following plugins are compatible on Linux systems.  Other plugins may work, but were designed to be run on Windows.  More Linux plugin support on the roadmap. 

* Amazon Echosystem Parser
* CCM Recently Used Apps
* Create Datasource Hashset
* File History
* Gui Test Plugins
* Hash Images
* Jump List AD
* MacFSEvents
* Parse PList
* SAM Parse
* Parse Shellbags
* Parse SQLite DBs
* Parse Usnj
* Plaso
* Process Activities Cache
* Parse Amache
* Process Appx Programs
* Process Appxreg Programs
* Parse EVTX
* Parse EVTX by Event ID
* Process Prefetch V41
* Process SRUDB
* Process Teracopy
* Process Windows Mail
* Remove Artifacts
* Shimache Parser
* Spotlight Parser
* Timesketch
* Volatility
* Webcache
* Windows Internals

## Need Help?
If you have any questions/comments/suggestions please let me know.  [Create an issue](https://github.com/markmckinnon/Autopsy-Plugins/issues/new).  Enjoy!


