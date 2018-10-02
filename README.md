# Autopsy-Plugins

This is a repository of Autopsy Python Plugins.  You can download all of them and place them in the python plugin directory.  All the plugins will recompile on execution.  

## Plugin Overview
Here is a brief overview of all of the plugins.

### Amazon Echosystem Parser
Parse the databases from an Amazon Alexa image.

### CCM Recently Used Apps
Parse the WMI(<insert acronym here>) database for Recently used apps.

### Create Preview Data Container
Create VHD expandable volumen and mount it.  Then read SQLite database of file extensions that can be exported to it and export those files matching the file extensions.  Finally it will unmount the VHD so it can be added back into an autopsy case.

### Cuckoo
Check the status of a [Cuckoo](https://cuckoosandbox.org/) server and submit files to it.

### Parse File History
Export the Catalog1.edb file and then call the command line version of the Expor_FileHistory.  A sqlite database that contains the File History information is created and then imported into the extracted view section of Autopsy.

### [Gui Test](./Gui_Test/README.md)
Example of the different types of things you can do with the GUI portion of Autopsy Python Plugins.

### [Gui Test With Settings](./Gui_Test_With_Settings/README.md)
Example of the saving and retrieving of settings from the GUI of an Autopsy Python Plugin.

### Hash Images
Hash raw, vmdk and vhdi images.  Like E01 hashing.

### Jump List AD
Export the JumpList AutoDestinations and then call the command line version of the Export_JL_Ad program.  A SQLite database that contains the JumpList information is created and then imported into the extracted view section of Autopsy.

### MacFSEvents
Export the .fsevents directory and run the FSEParser_v2.1.exe program against the exported data.  It will then import the SQLite database that was created from the program.

### MacOSX Recent
Export/Parse Mac recents.

### MacOSX Safari
Export/Parse Mac OSX safari.  A SQLite database that contains the Safari information is created and then imported into the extracted view section of Autopsy.

### Parse PList
Parse any plist and convert it to a SQLite database and then import the information into the extracted contant.

### SAM Parse
Export SAM Registry Hive and then call the command line version of SAM Parse program.  A SQLite database that contains SAM information is created then imported into the extracted view section of Autopsy.

### [Parse SQLite DBs](./Parse_SQLite_Databases/README.md)
Parse any SQLite files and import them into the extracted content section of Autopsy.

### [Parse SQLite DB Del Records](./Parse_SQLite_Del_Records/README.md)
Parse any SQLite databases and look for deleted records.  It will then create a SQLite database with the deleted records and then be imported into the extracted content section of Autopsy.

### Parse Shellbags
Export the NTUSER Hive(s) and then call the command line version of shell bags program.  A SQLite database that contains the shellbag information is created then imported into the extracted view section of Autopsy.

### Parse Usnj
Export the $UsnJrnl:$J and then call the command line version of parseusn program.  A SQLite database that contains the NTFS UsrJrnl information is created and imported into the extracted view section of Autopsy.

### Plaso
Execute plaso or import a plaso file.

### Parse Amache
Export the Amache Registry and then call the command line version of Export_Amache program.  A SQLite database contains the Amache information is created then imported into the extracted content view of Autopsy.

### Parse EVTX
Export the Windows Event Logs and then call the command line version of the Export_EVTX program.  A SQLite database that contains the Event Log information is created and imported into the extracted view section of Autopsy.

### Parse EVTX by Event ID
Export all the Windows Event Logs and thenc all the command line version of the Export_EVTX program.  A SQLite database that conains the Event Log information is created then imported into the extracted view section of Autopsy as a Table based on Event_Log_Id.  the user can then run the module again and extract user supplied events from the Evtx SQLite database.

### Process Appx Programs
Parse the SQLite database that has the Windows 10 Store/metro apps database.

### Process Appxreg Programs
Parse the registry to read the Windows 10 Store/metro apps.

### Process Facebook Chats
Parses the chats from facebook on a windows OS.

### Process Extract VSS
Example of the different types of things you can do with Autopsy plugin?

### Process Prefetch V41
Export the prefetch files and thenc all the command line version of the prefetch_parser.  A SQLite database that contains the prefetch information is created and then imported into the extracted view section of Autopsy.

### Process SRUDB
Export the System Resource Usage Database and then call the command line version of the Export SRUDB program.  A SQLite database that contains the Resource Usage information is created then imported into the extracted view of Autopsy.

### Process Windows Mail
Process Windows Mail store and added messages to communication manager.

### Shimache Parser
Export the System Registry Hive and then call the command line version of the shimache_parser program.  A SQLite database that contains the shimache information is created then imported into the extracted view section of Autopsy.

### Spotlight Parser
Parses the Spotlight data from the macos.

### Thumbcache Parser
Export all the thumbcache_*.db files in the image and then run the [thumbcache_viewer_cmd](https://github.com/thumbcacheviewer/thumbcacheviewer) program against them and export the embedded files to the ModuleOutput directory so that the files can then be added back into Autopsy.

### Thumbs Parser
Export all the thumbs.db files in the image and then run the [thumbs_viewer](https://github.com/thumbsviewer/thumbsviewer) program against them and export the embedded files to the ModuleOutput directory so that the files can then be added back into Autopsy.

### Volatility
Execute Volatility against a memory image.  It will ask the user for the directory where the Volatility executable reside then it will run volatility against the memory image using options the user specifies.

### Webcache
Module will export the WebcacheV01 file and then call the command line version of the Export_Esedb.  A SQLite database that contains the Webcache information is created then imported into the extracted view section of Autopsy.

### Windows Internals
Several windows plugins combined into one plugin.  You pick with checkboxes what you want it to do.

## Linux Compatible Plugins 
The following plugins are compatible on Linux systems.  Other plugins may work, but were designed to be run on Windows.  More Linux plugin support on the roadmap. 

* Volatility Plugins
* SQLite Plugins
* Amazon Echosystem Plugins
* Gui Test Plugins
* Process_Appx_Programs
* Hash_Images
* Process SRUDB

## Other Resources
You can read about some of the plugins at https://medium.com/@markmckinnon_80619

## Need Help?
If you have any questions/comments/suggestions please let me know.  [Create an issue](https://github.com/markmckinnon/Autopsy-Plugins/issues/new).  Enjoy!
