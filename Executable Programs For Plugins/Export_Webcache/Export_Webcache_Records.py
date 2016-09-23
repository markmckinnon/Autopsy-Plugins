# Export_Webcache_Records.py = Export the Webcache esedb to SQLite based on number of records
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
# python3 export_Webcache_Records.py /home/mark/webcachev01.dat Webcache.db3 Content 1000 20000

import pyesedb
from Database import SQLiteDb
import os
import sys
import re

# Setup dictionary for column types
Column_Dict = {0:'NULL', 1:'Text', 2:'Integer', 3:'Integer', 4:'Integer', 5:'Integer', 6:'Real', 7:'Real', 8:'Integer', 9:'Blob', \
              10:'Text', 11:'Blob', 12:'Text', 13:'Integer', 14:'Integer', 15:'Integer', 16:'Text', 17:'Integer'}

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
             out = "".join(uncompressed_data).join(last_char)
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
 
			  
args = sys.argv[1:]
File_To_Parse = args[0]
SQLite_DB_Name = args[1]
Table_Name = args[2]
Begin_Record_Number = args[3]
End_Record_Number = args[4]

SQLitedb = SQLiteDb()
SQLitedb.Open(SQLite_DB_Name)
file_object = open(File_To_Parse, "rb")
esedb_file = pyesedb.file()
esedb_file.open_file_object(file_object)
EsedbTable = esedb_file.get_table_by_name(Table_Name)
print ("Inserting records into table ==> " + Table_Name)
for i in range(int(Begin_Record_Number), int(End_Record_Number)):
   SQL_Bind_Values = []
   SQL_Statement_Table = 'Insert into ' + Table_Name + ' '
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
       Check_Column_Type(EsedbTable_Record, Column_Type, x, SQL_Bind_Values)
   SQLitedb.InsertBindValues(Table_Name, SQL_Statement_Columns, SQL_Bind_Variables, SQL_Bind_Values)
esedb_file.close()
del esedb_file
SQLitedb.Close()
del SQLitedb


	