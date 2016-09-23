# Export_EVTX.py = Python script to extract EVTX logs to a SQLite Database
#
# Copyright (C) 2016 Mark McKinnon (Mark.McKinnon@Davenport.edu)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>
#
# Version History:
#  Initial Version - Requires pyevtx python binding from the project libyal/libevtx
# 
# Usage Examples:
# python3 export_EVTX.py /home/mark/eventlog_directory event_logs.db3

import os
import sys
import pyevtx
import codecs
from Database import SQLiteDb
import ntpath
import argparse

table_name = 'Event_Logs'
table_columns = 'file_name text, Recovered_Record text, Computer_name text, Event_Identifier number, Event_Identifier_Qualifiers text, ' + \
                'Event_Level number, Event_Offset number, identifier number, Event_Source_Name text,' + \
                'Event_User_Security_Identifier text, Event_Time text, Event_time_epoch number, Event_detail_text text'
sql_ins_columns = 'file_name, recovered_record, Computer_name, Event_Identifier, Event_Identifier_Qualifiers, Event_Level, Event_Offset, ' + \
                'identifier, Event_Source_Name, Event_User_Security_Identifier, Event_Time, Event_time_epoch, Event_detail_text' 
sql_bind = '?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?'

def uprint(*objects, sep=' ', end='\n', file=sys.stdout):
    enc = file.encoding
    if enc == 'UTF-8':
        print(*objects, sep=sep, end=end, file=file)
    else:
        f = lambda obj: str(obj).encode(enc, errors='backslashreplace').decode(enc)
        print(*map(f, objects), sep=sep, end=end, file=file)

def get_filepaths(directory):

    file_paths = []  # List which will store all of the full filepaths.
    dir_paths = []

    # Walk the tree.
    for root, directories, files in os.walk(directory):
         for filename in files:
            # Join the two strings in order to form the full filepath.
            filepath = os.path.join(root, filename.upper())
            if '.EVTX' in filepath:
               file_paths.append(filepath)  # Add it to the list.

    return file_paths # Self-explanatory.


def parse_event_log(file_to_parse):

   
   file_object = open(file_to_parse, "rb")
   evtx_file = pyevtx.file()
   evtx_file.open_file_object(file_object)
   SQLitedb.CreateTempTable(table_name + '_temp', table_columns)   

   print (' Number of Records in Event Log ==> ', evtx_file.get_number_of_records())
   print (' Number of recovered Records in Event Log ==> ', evtx_file.get_number_of_recovered_records())

   for i in range (0, evtx_file.get_number_of_records()):
      event_record = []
      event_record.append(ntpath.basename(file_to_parse))
      event_string = ""
      evtx_record = evtx_file.get_record(i)
      event_record.append('N')
      if (evtx_record.get_computer_name() == None):
         event_record.append('NULL')
      else:
         event_record.append(evtx_record.get_computer_name())   
      event_record.append(evtx_record.get_event_identifier())   
      event_record.append(evtx_record.get_event_identifier_qualifiers())   
      event_record.append(evtx_record.get_event_level())   
      event_record.append(evtx_record.get_identifier())   
      event_record.append(evtx_record.get_offset())   
      if (evtx_record.get_source_name() == None):
         event_record.append('NULL')
      else:
         event_record.append(evtx_record.get_source_name())   
      if (evtx_record.get_user_security_identifier() == None):
         event_record.append('NULL')
      else:
         event_record.append(evtx_record.get_user_security_identifier())   
      event_record.append(evtx_record.get_written_time())
      event_record.append(evtx_record.get_written_time_as_integer()) 
      for x in range (0, evtx_record.get_number_of_strings()):
         if (evtx_record.get_string(x) == None):
            event_string = event_string + " \n"
         else:
            event_string = event_string + evtx_record.get_string(x) + " \n"
      event_record.append(event_string)	  
  
      SQLitedb.InsertBindValues(table_name + '_temp', sql_ins_columns, sql_bind, event_record) 


   if (SQLitedb.TableExists(table_name)):  
      SQLitedb.AppendTempToPermanentTable(table_name)
   else:
      SQLitedb.CreatePermanentTable(table_name)
   SQLitedb.DropTable(table_name + '_temp')


   
args = sys.argv[1:]
Directory_To_Parse = args[0]
SQLite_DB_Name = args[1]
print ('Dir is ', str(Directory_To_Parse))
print ('DB file is ', SQLite_DB_Name)
SQLitedb = SQLiteDb()
SQLitedb.Open(SQLite_DB_Name)

# Run the above function and store its results in a variable.   
Full_File_Paths = get_filepaths(Directory_To_Parse)

for files in Full_File_Paths:
   parse_event_log(files)
SQLitedb.Close()  

