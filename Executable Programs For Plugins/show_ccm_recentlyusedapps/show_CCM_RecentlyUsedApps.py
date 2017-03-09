#  This script is a modification to the show_CCM_RecentlyUsedApps.py script that can be found at 
#  https://github.com/fireeye/flare-wmi/blob/master/python-cim/samples/show_CCM_RecentlyUsedApps.py
#  
#  The additions I made was to make it so that the output from the script will be written to a 
#  SQLite database instead of to the screen.
#
#  To run the script you will need to install the python-cim form the fireeye/flare-wmi on github
#  https://github.com/fireeye/flare-wmi
#
import logging
import sqlite3
import os
import sys

from cim import CIM
from cim.objects import Namespace

def main(type_, path, SQLite_DB_Name):
    if type_ not in ("xp", "win7"):
        raise RuntimeError("Invalid mapping type: {:s}".format(type_))

    Values = ["FolderPath","ExplorerFileName","FileSize","LastUserName","LastUsedTime","TimeZoneOffset","LaunchCount","OriginalFileName","FileDescription","CompanyName","ProductName","ProductVersion","FileVersion","AdditionalProductCodes","msiVersion","msiDisplayName","ProductCode","SoftwarePropertiesHash","ProductLanguage","FilePropertiesHash","msiPublisher"]
    #print("\t".join(Values))
    
    try:
       os.remove(SQLite_DB_Name)
    except:
       print("File does not exist")
       
    con = sqlite3.connect(SQLite_DB_Name)
    # Create the table
    #con.execute("Pragma journal_mode=wal")
    con.execute("CREATE TABLE IF NOT EXISTS recently_used(FolderPath text, ExplorerFileName text, FileSize text, LastUserName text, LastUsedTime text, TimeZoneOffset text, LaunchCount text, OriginalFileName text, FileDescription text, CompanyName text, ProductName text, ProductVersion text, FileVersion text, AdditionalProductCodes text, msiVersion text, msiDisplayName text, ProductCode text, SoftwarePropertiesHash text, ProductLanguage text, FilePropertiesHash text, msiPublisher text)")

    c = CIM(type_, path)
    try:
        with Namespace(c, "root\\ccm\\SoftwareMeteringAgent") as ns:
            for RUA in ns.class_("CCM_RecentlyUsedApps").instances:
                RUAValues = []
                for Value in Values:
                    try:
                       if Value == "LastUsedTime":
                           Time = str(RUA.properties[Value].value)
                           ExcelTime = "{}-{}-{} {}:{}:{}".format(Time[0:4],Time[4:6],Time[6:8],Time[8:10],Time[10:12],Time[12:14])
                           RUAValues.append(ExcelTime)
                       elif Value == "TimeZoneOffset":
                           TimeOffset = '="{}"'.format(Time[-4:])
                           RUAValues.append(TimeOffset)
                       else:
                           RUAValues.append(str(RUA.properties[Value].value))
                    except KeyError:
                        RUAValues.append("")
                # Fill table
                sql_data = "','".join(RUAValues)
                sql_statement = "insert into recently_used values ('" + sql_data + "')"
                #print (sql_statement)                
                con.execute(sql_statement)

                #con.executemany("REPLACE INTO recently_used VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", RUAValues)
                #con.commit()

                #print("\t".join(RUAValues))
        con.commit()    
    except IndexError:
        print("Error In Run Exiting")
        #raise RuntimeError("CCM Software Metering Agent path 'root\\\\ccm\\\\SoftwareMeteringAgent' not found.")


#logging.basicConfig(level=logging.INFO)
args = sys.argv[1:]
type_ = args[0]
repo_path = args[1]
SQLite_DB_Name = args[2]
main(type_, repo_path, SQLite_DB_Name)
