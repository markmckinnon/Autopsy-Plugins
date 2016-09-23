# Export_Webcache_Records.py = Export the Webcache esedb to SQLite based
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
#  Initial Version - Requires pyesedb python binding from the project libyal/libesedb
# 
# Usage Examples:
# python3 export_Webcache.py /home/mark/webcachev01.dat Webcache.db3

import pyesedb
from Database import SQLiteDb
import os
import sys
import re
import subprocess 

# Setup dictionary for column types
Column_Dict = {0:'NULL', 1:'Text', 2:'Integer', 3:'Integer', 4:'Integer', 5:'Integer', 6:'Real', 7:'Real', 8:'Integer', 9:'Blob', \
              10:'Text', 11:'Blob', 12:'Text', 13:'Integer', 14:'Integer', 15:'Integer', 16:'Text', 17:'Integer'}

create_table_name = "All_Container_Data"  
create_table_columns = "EntryId Integer , ContainerId Integer, UrlHash Integer, AccessCount Integer, SyncTime Integer, " + \
                       " CreationTime Integer, ExpiryTime Integer, ModifiedTime Integer, AccessedTime Integer, " \
                       " Url Text, Filename Text, FileSize Integer, container_name text"
create_tab_columns = "EntryId Integer , ContainerId Integer, UrlHash Integer, AccessCount Integer, SyncTime text, " + \
                       " CreationTime text, ExpiryTime text, ModifiedTime text, AccessedTime text, " \
                       " Url Text, Filename Text, FileSize Integer, container_name text"
              
              
def ole_date_bin_to_datetime(ole_date_bin):
    """
        Converts a OLE date from a binary 8 bytes little endian hex form to a datetime
    """
    #Conversion to OLE date float, where:
    # - integer part: days from epoch (1899/12/30 00:00) 
    # - decimal part: percentage of the day, where 0,5 is midday
    date_float = unpack('<d', ole_date_bin)[0]
    date_decimal, date_integer = math.modf(date_float)
    date_decimal = abs(date_decimal)
    date_integer = int(date_integer)

    #Calculate the result
    res = datetime.datetime(1899, 12, 30) + datetime.timedelta(days=date_integer) #adding days to epoch
    res = res + datetime.timedelta(seconds = 86400*date_decimal) #adding percentage of the day
    return res

def Check_Column_Type(EsedbTable_Record, Column_Type, Column_Number, Record_List):
    if (Column_Type == 0):   # Null
       return "NULL"
    elif (Column_Type == 1): #Boolean
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('NULL')
       else:
          return Record_List.append(str(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore')))	
    elif (Column_Type == 2): #INTEGER_8BIT_UNSIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))
    elif (Column_Type == 3): #INTEGER_16BIT_SIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 4): #INTEGER_32BIT_SIGNED	
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))
    elif (Column_Type == 5): #CURRENCY
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 6): #INTEGER_8BIT_UNSIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_floating_point(Column_Number))
    elif (Column_Type == 7): #DOUBLE_64BIT
       return Record_List.append(EsedbTable_Record.get_value_data_as_floating_point(Column_Number))	
    elif (Column_Type == 8): #FLOAT_32BIT	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          return Record_List.append(ole_date_bin_to_datetime(EsedbTable_Record.get_value_data(Column_Number)))
    elif (Column_Type == 9): #BINARY_DATA
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          return Record_List.append(EsedbTable_Record.get_value_data(Column_Number))
    elif (Column_Type == 10): #TEXT	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          return Record_List.append(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
    elif (Column_Type == 11): #LARGE_BINARY_DATA
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          return Record_List.append(EsedbTable_Record.get_value_data(Column_Number))
    elif (Column_Type == 12): #LARGE_TEXT	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          compressed_text = EsedbTable_Record.get_value_data(Column_Number)
          comp_text = compressed_text[1]
          if comp_text == 24:
             #print ("This text is EXPRESS Compressed")
             return Record_List.append(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
          elif comp_text >= 23:
             #print ("This text is compressed using 7-bit")
             compressed_data_index = 0
             compressed_data = compressed_text
             uncompressed_data_index = 0
             compressed_data_size = len(compressed_data)
             value_16bit = 0
             bit_index = 0
             compressed_data_index = 1
             comp_data = 0
             uncompressed_data = []
             while compressed_data_index < compressed_data_size:
                comp_data = (compressed_data[compressed_data_index])
                value_16bit |= comp_data << bit_index
                uncompressed_data_index = uncompressed_data_index + 1
                uncompressed_data.append(chr(value_16bit & 0x7f))
                value_16bit >>= 7
                bit_index += 1
                if bit_index == 7:
                   uncompressed_data_index = uncompressed_data_index + 1
                   uncompressed_data.append(chr(value_16bit & 0x7f))
                   value_16bit >>= 7
                   bit_index = 0
                compressed_data_index += 1
             last_char = uncompressed_data.pop()
             out = "".join(uncompressed_data)
             return Record_List.append(out) 
          else:	
             # print ("This text is not compressed")
             return Record_List.append(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore'))
    elif (Column_Type == 13): #SUPER_LARGE_VALUE
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 14): #INTEGER_32BIT_UNSIGNED	
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 15): #INTEGER_64BIT_SIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
    elif (Column_Type == 16): #GUID	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          return Record_List.append(str(EsedbTable_Record.get_value_data(Column_Number).decode('utf-16', 'ignore')))
    elif (Column_Type == 17): #INTEGER_16BIT_UNSIGNED
       return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
 
			  
def Parse_ESEDB_File(File_To_Parse, SQLite_DB_Name):
   file_object = open(File_To_Parse, "rb")
   esedb_file = pyesedb.file()
   esedb_file.open_file_object(file_object)
   Num_Of_tables = esedb_file.get_number_of_tables()
   print ("The number of tables is ==> ", Num_Of_tables)
   SQLitedb.CreateTable('ESEDB_Master_Table','Tab_Name text')
   SQLitedb.CreateTable('ESEDB_Empty_Tables', 'Tab_Name Text')
   for i in range (0, Num_Of_tables):
       SQL_Statement = ''
       Table = esedb_file.get_table(i)
       Table_name = Table.get_name()
       Template_Name = Table. get_template_name()
       Table_Num_Columns = Table.get_number_of_columns()
       Table_Num_Records = Table.get_number_of_records()
       print ("Table Name is ==> ", Table_name, " Number of records is ==> ", Table_Num_Records)
       if (Table_Num_Records > 0):
          SQLitedb.InsertValues('ESEDB_Master_Table','Tab_Name', "'" + Table_name + "'")
          SQL_Statement = 'Create Temp Table '+ Table_name + '_Temp ('
          Table_Record = Table.get_record(0)
          Column_Name = Table_Record.get_column_name(0)
          Column_Type = Table_Record.get_column_type(0)
          SQLitedb.CreateTable(Table_name, SQLitedb.Check_SQL_Reserved_Word(Column_Name) + ' ' + Column_Dict[Column_Type])
          for x in range(1, Table_Num_Columns):
            Column_Name = Table_Record.get_column_name(x)
            Column_Type = Table_Record.get_column_type(x)
            SQL_Statement = SQL_Statement + ', ' + SQLitedb.Check_SQL_Reserved_Word(Column_Name) + '    ' + Column_Dict[Column_Type]
            SQLitedb.AddColumn(Table_name, SQLitedb.Check_SQL_Reserved_Word(Column_Name) + ' ' + Column_Dict[Column_Type])
          SQL_Statement = SQL_Statement + ');'
          Num_Records_Begin = 0
          Num_Records_End = 20000
          while True:
             if Table_Num_Records < 19999:
                ESEDB_Process_Records.append(["Export_Webcache_Records.exe", File_To_Parse, SQLite_DB_Name, Table_name, str(Num_Records_Begin), str(Table_Num_Records)])
                break
             elif Table_Num_Records < Num_Records_End:
                ESEDB_Process_Records.append(["Export_Webcache_Records.exe", File_To_Parse, SQLite_DB_Name, Table_name, str(Num_Records_Begin), str(Table_Num_Records)])
                break
             else:
                ESEDB_Process_Records.append(["Export_Webcache_Records.exe", File_To_Parse, SQLite_DB_Name, Table_name, str(Num_Records_Begin), str(Num_Records_End)])
             Num_Records_Begin = Num_Records_Begin + 20000
             Num_Records_End = Num_Records_End + 20000
       else:
          SQLitedb.InsertValues('ESEDB_Empty_Tables','Tab_Name', "'" + Table_name + "'")
	  
   esedb_file.close()

def Create_Permanent_Tables():

   Table_Names = SQLitedb.SelectAllRows("Select tab_name from ESEDB_Master_Table where Tab_name not in (Select tab_name from ESEDB_Empty_tables)")
   for Table_Name in Table_Names:
        Table_name = str(Table_Name[0])
        print ("creating permanent " + str(Table_name), str(Table_name) + "_temp")
        SQLitedb.CreatePermanentTable(Table_name, str(Table_name) + "_temp")

def Populate_ESEDB_DB(File_To_Parse, SQLite_DB_Name):
   for Record_To_Process in ESEDB_Process_Records:
      #print (Record_To_Process)
      #print (Record_To_Process[0])
      subprocess.run(Record_To_Process)

def Consolidate_Data():
   Table_Names = SQLitedb.SelectAllRows("select 'container_'||containerid from containers where 'container_'||containerid in " + \
                                         " (select lower(name) from sqlite_master);")      
   SQLitedb.CreateTable(create_table_name, create_table_columns)
   for Table_Name in Table_Names:
        Table_name = str(Table_Name[0])
        print ("Inserting From " + str(Table_name))
        ins_stmt = "insert into all_container_data (entryid, containerid, urlhash, accessCount, synctime, " + \
                   " creationtime, expirytime, modifiedtime, accessedtime, url, filename, filesize) " + \
                   " Select entryid, a.containerid, urlhash, accessCount, synctime, creationtime, expirytime, " + \
                   " modifiedtime, accessedtime, url, filename, filesize " + \
                   " from " + Table_name + " a, containers b where a.containerid = b.containerid;"
        SQLitedb.InsertSelect(ins_stmt)
   Container_Info = SQLitedb.SelectAllRows("select distinct name, containerid from containers")      
   for Container_info in Container_Info:
        container_name = str(Container_info[0])
        container_name = container_name[:-1]
        container_id = str(Container_info[1])
        print ("Updating From " + str(container_name))
        Upd_stmt = "Update All_Container_data set container_name = '" + container_name + "' where containerid = " + container_id + ";"
        print (Upd_stmt)
        SQLitedb.UpdateTable(Upd_stmt)
   Upd_stmt = "Update all_container_data set synctime = (SUBSTR(synctime,1,11)-11644473600) where synctime <> 0;"
   SQLitedb.UpdateTable(Upd_stmt)
   Upd_stmt = "Update all_container_data set creationtime = (SUBSTR(creationtime,1,11)-11644473600) where creationtime <> 0;"
   SQLitedb.UpdateTable(Upd_stmt)
   Upd_stmt = "Update all_container_data set expirytime = (SUBSTR(expirytime,1,11)-11644473600) where expirytime <> 0;"
   SQLitedb.UpdateTable(Upd_stmt)
   Upd_stmt = "Update all_container_data set modifiedtime = (SUBSTR(modifiedtime,1,11)-11644473600) where modifiedtime <> 0;"
   SQLitedb.UpdateTable(Upd_stmt)
   Upd_stmt = "Update all_container_data set accessedtime = (SUBSTR(accessedtime,1,11)-11644473600) where accessedtime <> 0;"
   SQLitedb.UpdateTable(Upd_stmt)
   SQLitedb.CreateTable("All_Containers", create_tab_columns)
   Insert_stmt = "insert into All_Containers select EntryId, ContainerId, UrlHash, AccessCount, " + \
                 "datetime(SyncTime, 'unixepoch') SyncTime, datetime(CreationTime,'unixepoch') CreationTime, " + \
                 "datetime(ExpiryTime,'unixepoch') ExpiryTime, datetime(ModifiedTime,'unixepoch') ModifiedTime, " + \
                 "datetime(AccessedTime,'unixepoch') AccessTime, Url, Filename, FileSize, container_name from all_container_data;"
   SQLitedb.InsertSelect(Insert_stmt)
   
   

args = sys.argv[1:]
File_To_Parse = args[0]
SQLite_DB_Name = args[1]
print ('Webcache is ', str(File_To_Parse))
print ('DB file is ', SQLite_DB_Name)
        
SQLitedb = SQLiteDb()
SQLitedb.RemoveDB_File(SQLite_DB_Name)
SQLitedb.Open(SQLite_DB_Name)
ESEDB_Process_Records = []

Parse_ESEDB_File(File_To_Parse,SQLite_DB_Name)

SQLitedb.Close()

Populate_ESEDB_DB(File_To_Parse,SQLite_DB_Name)

SQLitedb.Open(SQLite_DB_Name)
Consolidate_Data()
SQLitedb.Close()
	