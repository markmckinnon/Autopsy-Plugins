# Export_SRUDB.py = Python script to extract the System Resource Usage to a SQLite Database
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
# python3 export_srudb.py srudb.dat srudb.db3

from Database import SQLiteDb
import os
import sys
import re
import datetime
import math
from struct import unpack
import pyesedb


# Setup dictionary for column types
Column_Dict = {0:'NULL', 1:'Text', 2:'Integer', 3:'Integer', 4:'Integer', 5:'Integer', 6:'Real', 7:'Real', 8:'Text', 9:'Blob', \
              10:'Text', 11:'Blob', 12:'Text', 13:'Integer', 14:'Integer', 15:'Integer', 16:'Text', 17:'Integer'}
Table_Dict = {'SruDbIdMapTable':'SruDbIdMapTable','{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}':'Application_Resource_Usage', \
              '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}':'Energy_Usage_Data','{97C2CE28-A37B-4920-B1E9-8B76CD341EC5}':'Energy_Estimation_Provider', \
			  '{973F5D5C-1D90-4944-BE8E-24B94231A174}':'Network_Usage','{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}':'Windows_Push_Notification', \
			  '{DD6636C4-8929-4683-974E-22C046A43763}':'Network_Connectivity', 'MSysObjects':'MSysObjects', \
			  'MSysObjectsShadow':'MSysObjectsShadow', 'MSysObjids':'MSysObjids', 'MSysLocales':'MSysLocales', \
			  'SruDbCheckpointTable':'SruDbCheckpointTable', '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT':'Energy_Usage_Provider'}
Table_Rev_Dict = {'SruDbIdMapTable':'SruDbIdMapTable','Application_Resource_Usage':'{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}', \
              'Energy_Usage_Data':'{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}','Energy_Estimation_Provider':'{97C2CE28-A37B-4920-B1E9-8B76CD341EC5}', \
			  'Network_Usage':'{973F5D5C-1D90-4944-BE8E-24B94231A174}','Windows_Push_Notification':'{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}', \
			  'Network_Connectivity':'{DD6636C4-8929-4683-974E-22C046A43763}', 'MSysObjects':'MSysObjects', \
			  'MSysObjectsShadow':'MSysObjectsShadow', 'MSysObjids':'MSysObjids', 'MSysLocales':'MSysLocales', \
			  'SruDbCheckpointTable':'SruDbCheckpointTable','Energy_Usage_Provider':'{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT'} 
			  
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
    elif (Column_Type == 8): #DATETIME	
       #return Record_List.append(EsedbTable_Record.get_value_data_as_integer(Column_Number))	
       if (EsedbTable_Record.get_value_data(Column_Number) == None):
          return Record_List.append('')
       else:
          #print (EsedbTable_Record.get_value_data(Column_Number))
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
 
			  
def Parse_ESEDB_File(File_To_Parse):
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
       Table_name = Table_Dict[Table.get_name()]
       Template_Name = Table. get_template_name()
       Table_Num_Columns = Table.get_number_of_columns()
       Table_Num_Records = Table.get_number_of_records()
       print ("Table Name is ==> ", Table_name)
       if (Table_Num_Records > 0):
          SQLitedb.InsertValues('ESEDB_Master_Table','Tab_Name', "'" + Table_name + "'")
          SQL_Statement = 'Create Temp Table '+ Table_name + '_Temp ('
          Table_Record = Table.get_record(0)
          Column_Name = Table_Record.get_column_name(0)
          Column_Type = Table_Record.get_column_type(0)
          SQLitedb.CreateTempTable(Table_name + '_Temp', SQLitedb.Check_SQL_Reserved_Word(Column_Name) + ' ' + Column_Dict[Column_Type])
          for x in range(1, Table_Num_Columns):
            Column_Name = Table_Record.get_column_name(x)
            Column_Type = Table_Record.get_column_type(x)
            SQL_Statement = SQL_Statement + ', ' + SQLitedb.Check_SQL_Reserved_Word(Column_Name) + '    ' + Column_Dict[Column_Type]
            SQLitedb.AddColumn(Table_name + '_Temp', SQLitedb.Check_SQL_Reserved_Word(Column_Name) + ' ' + Column_Dict[Column_Type])
          SQL_Statement = SQL_Statement + ');'
       else:
          SQLitedb.InsertValues('ESEDB_Empty_Tables','Tab_Name', "'" + Table_name + "'")
   esedb_file.close()

def Create_Permanent_Tables():

   Table_Names = SQLitedb.SelectAllRows("Select tab_name from ESEDB_Master_Table where Tab_name not in (Select tab_name from ESEDB_Empty_tables)")
   for Table_Name in Table_Names:
        Table_name = str(Table_Name[0])
        print ("creating permanent " + str(Table_name), str(Table_name) + "_temp")
        SQLitedb.CreatePermanentTable(Table_name, str(Table_name) + "_temp")
   SQLitedb.DropTable('MSysObjects')
   SQLitedb.DropTable('MSysObjectsShadow')
   SQLitedb.DropTable('MSysObjids')
   SQLitedb.DropTable('MSysLocales')
   SQLitedb.DropTable('ESEDB_Master_Table')
   SQLitedb.DropTable('ESEDB_Empty_Tables')

def Populate_ESEDB_DB(File_To_Parse):
   file_object = open(File_To_Parse, "rb")
   esedb_file = pyesedb.file()
   esedb_file.open_file_object(file_object)
   Table_Names = SQLitedb.SelectAllRows("Select tab_name from ESEDB_Master_Table where Tab_name not in (Select tab_name from ESEDB_Empty_tables);")
   for Table_Name in Table_Names:
        Table_name = str(Table_Name[0])
        print ("Inserting into table " + str(Table_name))
        EsedbTable = esedb_file.get_table_by_name(Table_Rev_Dict[Table_Name[0]])
        for i in range(0,EsedbTable.get_number_of_records()):
           SQL_Bind_Values = []
           SQL_Statement_Table = 'Insert into ' + Table_Name[0] + '_temp'
           EsedbTable_Record = EsedbTable.get_record(i)
           EsedbTable_Num_Columns = EsedbTable.get_number_of_columns()
           Column_Name = EsedbTable_Record.get_column_name(0)
           SQL_Statement_Columns = SQLitedb.Check_SQL_Reserved_Word(Column_Name)
           SQL_Bind_Variables = SQLitedb.create_question_bind_variables(EsedbTable.get_number_of_columns())
           Column_Type = EsedbTable_Record.get_column_type(0)
           Check_Column_Type(EsedbTable_Record, Column_Type, 0, SQL_Bind_Values)
           for x in range(1,EsedbTable.get_number_of_columns()):
               Column_Name = EsedbTable_Record.get_column_name(x)
               SQL_Statement_Columns = SQL_Statement_Columns + ',' + SQLitedb.Check_SQL_Reserved_Word(Column_Name)
               Column_Type = EsedbTable_Record.get_column_type(x)
               if Column_Name == 'IdBlob':
                  Check_Column_Type(EsedbTable_Record, 10, x, SQL_Bind_Values)
               else:
                  Check_Column_Type(EsedbTable_Record, Column_Type, x, SQL_Bind_Values)
           SQLitedb.InsertBindValues(Table_Name[0] + '_temp', SQL_Statement_Columns, SQL_Bind_Variables, SQL_Bind_Values)
   esedb_file.close()

def Post_Database_Processing():

   Table_Names = SQLitedb.SelectAllRows("Select tab_name from ESEDB_Master_Table where Tab_name not in (Select tab_name from ESEDB_Empty_tables) and tab_name not like 'MSys%' and Tab_name not like 'Sru%';")
   for Table_Name in Table_Names:
        Table_name = str(Table_Name[0])
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_Date text')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_time text')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_Time_Hour integer')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_time_Minute integer')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_time_Day_Of_Week integer')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_epochtime integer')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_Date_Month text')
        SQLitedb.AddColumn(Table_name + '_temp', 'SRUM_Write_Date_Day Integer')
        SQL_Statement = "update " + Table_name + "_temp set SRUM_Write_Date = date(timestamp), " \
                             "SRUM_Write_Time = time(timestamp), SRUM_Write_Time_Hour = strftime('%H', timestamp), " \
                             "srum_Write_Time_Minute = strftime('%M', timestamp), srum_Write_Time_Day_Of_Week = " \
					         "(case when strftime('%w', timestamp) = '0' then 'Sunday' " \
                             "when strftime('%w', timestamp) = '1' then 'Monday' when strftime('%w', timestamp) = '2' then 'Tuesday' " \
                             "when strftime('%w', timestamp) = '3' then 'Wednesday' when strftime('%w', timestamp) = '4' then 'Thursday' " \
                             "when strftime('%w', timestamp) = '5' then 'Friday' when strftime('%w', timestamp) = '6' then 'Saturday' " \
                             "end), srum_Write_epochtime = strftime('%s', timestamp), srum_write_Date_Day = strftime('%d', timestamp);"
        #print (SQL_Statement)
        SQLitedb.UpdateTable(SQL_Statement)
        SQL_Statement = "update " + Table_name + "_Temp set SRUM_Write_Date_Month  = " \
	                         "(case when strftime('%m', timestamp) = '01' then 'January' " \
                             "when strftime('%m', timestamp) = '02' then 'February' " \
                             "when strftime('%m', timestamp) = '03' then 'March' " \
                             "when strftime('%m', timestamp) = '04' then 'April' " \
                             "when strftime('%m', timestamp) = '05' then 'May' " \
                             "when strftime('%m', timestamp) = '06' then 'June' " \
                             "when strftime('%m', timestamp) = '07' then 'July' " \
                             "when strftime('%m', timestamp) = '08' then 'August' " \
                             "when strftime('%m', timestamp) = '09' then 'September' " \
                             "when strftime('%m', timestamp) = '10' then 'October' " \
                             "when strftime('%m', timestamp) = '11' then 'November' " \
                             "when strftime('%m', timestamp) = '07' then 'December' end);"
        #print (SQL_Statement)
        SQLitedb.UpdateTable(SQL_Statement)
   

args = sys.argv[1:]
File_To_Parse = args[0]
SQLite_DB_Name = args[1]

SQLitedb = SQLiteDb()
SQLitedb.RemoveDB_File(SQLite_DB_Name)
SQLitedb.Open(SQLite_DB_Name)

Parse_ESEDB_File(File_To_Parse)
Populate_ESEDB_DB(File_To_Parse)
Post_Database_Processing()

Create_Permanent_Tables()
SQLitedb.Close()

	