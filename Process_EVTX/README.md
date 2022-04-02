# Parse Windows EventLogs
ParseEvtx will parse Windows EventLogs and display the output. This plugin utilises "export_evtx.exe" to parse the EventLogs into an SQLite database.

The parser can be run across all EventLogs at once, or you can select individual EventLogs to run.

The output will display under Data Artifacts in the main Autopsy window.

## Install Process
This section will go over the different ways that you can install the ParseEvtx Plugin.

### Only install ParseEvtx Plugin
1. To install the plugin first you must [download a ZIP](https://github.com/markmckinnon/Autopsy-Plugins/archive/master.zip) file containing all of the plugins.  This ZIP file contains a number of Autopsy plugins.
2. [Unzip the ZIP file.](https://support.microsoft.com/en-us/help/14200/windows-compress-uncompress-zip-files)
3. Move the folder named Process_Evtx to the plugin directory.
  * To figure out the plugin directory you can go to Tools > Python Plugins inside of the Autopsy Menu System and it should open the folder where the plugin should go.
4. Restart Autopsy if it is running.

### Executable Installer (Windows Only)
1. Download the [installer](https://github.com/markmckinnon/Autopsy-Plugins/releases/download/v1.0/Autopsy_Python_Plugins.exe).
2. Run the installer following the prompts.

## Running the Plugin
1. To run the plugin you can right click a folder inside of your datasource and run the Run Ingestion Modules options.
2. A popup will appear.  Select ParseEvtx in the list of plugins. 
3. Choose which EventLogs you wish to process.
4. When entering an EventLog name into the field, ensure that the names are entered BEFORE selecting the Other checkbox. Names of eventlogs should be separated by a comma.
5. Hit Finish.
6. Your results should appear inside of Extracted Content on the main Autopsy screen.