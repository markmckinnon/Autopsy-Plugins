# amacache_parser.py = Python script to parse the amcache and save to a SQLite Database
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
#  Initial Version - Requires Registry python scripts to be installed
# 
# Usage Examples:
# python3 export_EVTX.py amcache.hve amacache.db3

import sys
import os
from Registry import Registry
from Database import SQLiteDb

cache_val_desc = {"0":"Product Name", "1":"Company Name", "2":"File version number only", "3":"Language code (1033 for en-US)", \
                  "4":"SwitchBackContext", "5":"File Version", "6":"File Size (in bytes)", "7":"PE Header field - SizeOfImage", \
                  "8":"Hash of PE Header (unknown algorithm)", "9":"PE Header field - Checksum", "a":"Unknown", "b":"Unknown", \
                  "c":"File Description", "d":"Unknown, maybe Major & Minor OS version", "f":"Linker (Compile time) Timestamp", \
                  "10":"Unknown", "11":"Last Modified Timestamp", "12":"Created Timestamp", "15":"Full path to file", "16":"Unknown", \
                  "17":"Last Modified Timestamp 2", "100":"Program ID", "101":"SHA1 hash of file"}
cache_sql_col = {"0":"Product_Name", "1":"Company_Name", "2":"File_version_number", "3":"Language_code", \
                  "4":"SwitchBackContext", "5":"File_Version", "6":"File_Size", "7":"PE_Header_field_SizeOfImage", \
                  "8":"Hash_PE_Header", "9":"PE_Header_Checksum", "a":"Unknown_a", "b":"Unknown_b", \
                  "c":"File_Description", "d":"Unknown_d", "f":"Linker_Compile_Timestamp", \
                  "10":"Unknown_10", "11":"Last_Modified_Timestamp", "12":"Created_Timestamp", "15":"Full_path_to_file", "16":"Unknown_16", \
                  "17":"Last_Modified_Timestamp_2", "100":"Program_ID", "101":"SHA1_hash_of_file"}
cache_val_type = {"0":"string", "1":"string", "2":"string", "3":"int", "4":"int", "5":"string", "6":"int", "7":"int", \
                  "8":"string", "9":"int", "a":"int", "b":"int", "c":"string", "d":"int", "f":"string", \
                  "10":"int", "11":"string", "12":"string", "15":"string", "16":"int", "17":"string", "100":"string", "101":"string"}

cache_pval_desc = {"0":"Program Name", "1":"Program Version", "2":"Publisher", "3":"Language code (1033 for en-US)", \
                  "4":"Not Seen", "5":"Unknown Flags", "6":"Entry Type (usually AddRemoveProgram)", "7":"Registry Uninstall Key", \
                  "8":"Not Seen", "9":"Not Seen", "a":"Install Date", "b":"Unknown", \
                  "c":"Not Seen", "d":"List Of File Paths", "f":"Product Code (GUID)", \
                  "10":"Package Code (GUID)", "11":"MSI Product Code (GUID)", "12":"MSI Package Code (GUID)", "13":"Unkown", \
                  "14":"Unknown", "15":"Unknown", "16":"Unknown", "17":"Unknown", "18":"Unknown", "Files":"Files"}
cache_psql_col = {"0":"Program_Name", "1":"Program_Version", "2":"Publisher", "3":"Language_code", \
                  "4":"Not_Seen_4", "5":"Unknown_Flags_5", "6":"Entry_Type", "7":"Registry_Uninstall_Key", \
                  "8":"Not_Seen_8", "9":"Not_Seen_9", "a":"Install_Date", "b":"Unknown_b", \
                  "c":"Not_Seen_c", "d":"List_Of_File_Paths", "f":"Product_Code_GUID", \
                  "10":"Package_Code_GUID", "11":"MSI_Product_Code_GUID", "12":"MSI_Package_Code_GUID", "13":"Unknown_13", \
                  "14":"Unknown_14", "15":"Unknown_15", "16":"Unknown_16", "17":"Unknown_17", "18":"Unknown_18", "Files":"Files"}
cache_pval_type = {"0":"string", "1":"string", "2":"string", "3":"string", "4":"int", "5":"int", "6":"string", "7":"binary", \
                  "8":"int", "9":"int", "a":"string", "b":"string", "c":"string", "d":"binary", "f":"string", \
                  "10":"string", "11":"binary", "12":"binary", "13":"int", "14":"int", "15":"int", "16":"binary", "17":"string", "18":"int", \
                  "Files":"binary"}

table_name_1 = 'File'
table_col_1 = 'Volume_id text, file_entry text, Product_Name text, Company_Name text, File_Version_Number text, Language_Code number, ' + \
              'SwitchBackContext number, File_Version text, File_Size number, PE_Header_Field_SizeOfImage number, Hash_Pe_Header text, ' + \
              'PE_Header_Checksum number, Unknown_a number, Unknown_b Number, File_Description text, Unknown_d number, ' + \
              'Linker_Compile_Timestamp text, Unknown_10 number, Last_Modified_Timestamp text, Created_Timestamp text, ' + \
              'Full_Path_To_File text, Unknown_16 number, Last_Modified_Timestamp_2 text, Program_Id text, SHA1_Hash_Of_File text, ' + \
              'Reg_Key_WriteTime text, Volume_Id_WriteTime text'
table_name_2 = 'Program'
table_col_2 = 'program_id text, Program_Name text, Program_version text, publisher text, Language_Code number, Not_Seen_4 number, ' + \
              'Unknown_Flags_5 number, Entry_Type text, registry_uninstall_key text, Not_seen_8 Number, Not_seen_9 number, ' + \
              'Install_date text, Unknown_b text, Not_Seen_c text, List_of_file_paths text, product_code_guid text, ' + \
              'Package_code_GUID text, MSI_Product_Code_GUID text, MSI_Package_Code_GUID text, Unknown_13 number, Unknown_14 number, ' + \
              'Unknown_15 number, Unknown_16 text, unknown_17 text, Unknown_18 number, files text, Reg_Key_WriteTime text'
table_name_3 = 'Program_File'
table_col_3 = 'Program_id text, Volume_id text, File_Entry text'
table_name_4 = 'Program_Filepaths'
table_col_4 = 'Program_Id text, file_path text'
table_name_5 = 'Orphan'
table_col_5 = 'Volume_id text, File_Entry text, Reg_Key_WriteTime text'

Unassoc_Progs = 'create table unassociated_programs as ' + \
                "select 'Unassociated' 'Program_Name',program_id, a.volume_id, volume_id_writetime, a.file_entry, a.reg_key_writetime, " + \
                'sha1_hash_of_file, full_path_to_file, File_size, file_version, file_version_number, file_description, ' + \
                'Pe_Header_Field_SizeOfImage, hash_PE_Header, PE_Header_Checksum, ' + \
                "created_timestamp, last_modified_timestamp, last_modified_timestamp_2, linker_compile_timestamp, " + \
                'language_code from file a, orphan d where a.volume_id = d.volume_id and a.file_entry = d.file_entry;'
                
Program_Entries = "create table program_entries as Select program_id, Reg_key_writetime, program_name, program_version, " + \
                  "publisher, install_date, unknown_b 'Install_Date_2', language_code, " + \
                  "entry_type 'Install Source', registry_uninstall_key, '' 'file_paths' from program"
                  
Associated_progs = "Create table associated_file_entries as " + \
                   "select Program_name, c.program_id, a.volume_id, volume_id_writetime 'Volumeid_writetime', " + \
                   "a.file_entry, a.reg_key_writetime 'file_id_last_writetime', full_path_to_file, '' 'File_Extension', File_size, " + \
                   "file_version, file_description, pe_header_field_sizeofImage 'PEHeaderSize', hash_pe_header, pe_header_checksum, " + \
                   "created_timestamp, last_modified_timestamp, last_modified_timestamp_2, linker_compile_timestamp, " + \
                   "a.language_code from file a, program b, program_file c where a.volume_id = c.volume_id " + \
                   "and a.file_entry = c.file_entry and b.program_id = c.program_id;"
                   
def parse_orphan(registry):
    programs = registry.open("root\\Orphan")
    for progs in programs.subkeys():
        orphan_sub = progs.name()
        reg_key_write_time = progs.timestamp()
        file_val = orphan_sub.split('@')
        #file_val.append(service.name())
        file_val2 = "'" + file_val[0] + "','" + file_val[1] + "', '" + str(reg_key_write_time) + "'"
        SQLitedb.InsertValues(table_name_5 + "_Temp", "Volume_id, File_entry, reg_key_writetime", file_val2)

def parse_programs(registry):
    programs = registry.open("root\\Programs")
    for progs in programs.subkeys():
        prog_sub = registry.open("root\\Programs\\" + progs.name())
        sql_ins_columns = []
        sql_val_columns = []
        sql_ins_columns.append("Program_id")
        sql_val_columns.append(progs.name())
        sql_ins_columns.append("Reg_Key_WriteTime")
        sql_val_columns.append(progs.timestamp())

        for prog in prog_sub.values():
           if prog.name() == "16":
              sql_ins_columns.append(cache_psql_col[prog.name()]) 
              sql_val_columns.append("Need to Parse")
           elif prog.name() == "Files":
              for file in  prog.value():
                 if ('@' in file):
                    file_val = file.split('@')
                    file_val2 = "'" + file_val[0] + "','" + file_val[1] + "','" + progs.name() + "'"
                    SQLitedb.InsertValues(table_name_3 + "_Temp", "Volume_id, File_entry, program_id", file_val2)
           elif prog.name() == "a":
              sql_ins_columns.append(cache_psql_col[prog.name()]) 
              sql_val_columns.append(str(prog.value()))
           elif prog.name() == "d":
              for file_path in prog.value():
                 if len(file_path) > 0:
                    f_path = "'" + file_path + "','" + progs.name() + "'"
                    SQLitedb.InsertValues(table_name_4 + "_Temp", "file_path, program_id", f_path)
           elif prog.name() == "7":
              p_val = prog.value()
              sql_ins_columns.append(cache_psql_col[prog.name()]) 
              sql_val_columns.append(p_val[0])
           elif prog.name() == "11":
              p_val = prog.value()
              sql_ins_columns.append(cache_psql_col[prog.name()]) 
              sql_val_columns.append(p_val[0])
           elif prog.name() == "12":
              p_val = prog.value()
              sql_ins_columns.append(cache_psql_col[prog.name()]) 
              sql_val_columns.append(p_val[0])
           else:
              sql_ins_columns.append(cache_psql_col[prog.name()]) 
              sql_val_columns.append(prog.value())
        sql_bind_values = SQLitedb.create_question_bind_variables(len(sql_ins_columns))
        SQLitedb.InsertBindValues(table_name_2 + "_Temp", ', '.join(sql_ins_columns), sql_bind_values, sql_val_columns)

        
def parse_files(registry):
    services = registry.open("root\\File")
    for vol_id in services.subkeys():
        vol_id_name = "root\\File\\" + vol_id.name()
        prog_sub = registry.open(vol_id_name)
        num_subkeys = prog_sub.subkeys_number()
        if (prog_sub.subkeys_number() > 0):
           for prog_subkeys in prog_sub.subkeys():
              sql_ins_columns = []
              sql_val_columns = []
              sql_ins_columns.append("Volume_Id")
              sql_val_columns.append(vol_id.name())
              sql_ins_columns.append("file_entry")
              sql_val_columns.append(prog_subkeys.name())
              sql_ins_columns.append("Reg_Key_WriteTime")
              sql_val_columns.append(prog_subkeys.timestamp())
              sql_ins_columns.append("Volume_Id_WriteTime")
              sql_val_columns.append(prog_sub.timestamp())
              for prog in prog_subkeys.values():
                  #print ("Value Name ==> ", prog.name(), "Value Value ==> ", prog.value()) 
                  sql_ins_columns.append(cache_sql_col[prog.name()]) 
                  sql_val_columns.append(prog.value())                      
              sql_bind_values = SQLitedb.create_question_bind_variables(len(sql_ins_columns))
              SQLitedb.InsertBindValues(table_name_1 + "_Temp", ', '.join(sql_ins_columns), sql_bind_values, sql_val_columns)

def Consolidate_Data():
    SQLitedb.UpdateTable(Unassoc_Progs)
    SQLitedb.UpdateTable(Program_Entries)
    p_id = SQLitedb.SelectAllRows("Select distinct a.program_id from program a, program_filepaths b where a.program_id = b.program_id")      
    for prog_id in p_id:
        program_id = str(prog_id[0])
        #print ("Updating From " + str(program_id))
        path_id = SQLitedb.SelectAllRows("select file_path from program_filepaths where  program_id = '" + program_id + "';")
        path_values = []
        for path in path_id:        
            path_values.append(path[0])     
        Upd_stmt = "Update program_entries set file_paths = '" + ' '.join(path_values) + "' where program_id = '" + program_id + "';"
        #print (Upd_stmt)
        SQLitedb.UpdateTable(Upd_stmt)
    SQLitedb.UpdateTable(Associated_progs)
    File_id = SQLitedb.SelectAllRows("SELECT ROWID, FULL_PATH_TO_FILE FROM associated_file_entries")
    datetime_upd = " set created_timestamp = DATETIME((SUBSTR(created_timestamp,1,11)-11644473600),'UNIXEPOCH'), " + \
                   "last_modified_timestamp = DATETIME((SUBSTR(last_modified_timestamp,1,11)-11644473600),'UNIXEPOCH'), " + \
                   "last_modified_timestamp_2 = DATETIME((SUBSTR(last_modified_timestamp_2,1,11)-11644473600),'UNIXEPOCH'), " + \
                   "linker_compile_timestamp = DATETIME((SUBSTR(linker_compile_timestamp,1,11)-11644473600),'UNIXEPOCH'); "
    SQLitedb.UpdateTable("Update associated_File_entries " + datetime_upd)                   
    SQLitedb.UpdateTable("Update unassociated_programs " + datetime_upd)                   
    datetime_upd = " set install_date = DATETIME((SUBSTR(install_date,1,11)-11644473600),'UNIXEPOCH'), " + \
                   " install_date_2 = DATETIME((SUBSTR(install_date_2,1,11)-11644473600),'UNIXEPOCH');"
    SQLitedb.UpdateTable("Update program_entries " + datetime_upd)                   
    for f_id in File_id:
        rowid = str(f_id[0])
        filename, file_extension = os.path.splitext(f_id[1])
        Upd_stmt = "Update associated_file_entries set file_extension = '" + file_extension + "' where rowid = " + rowid + ";"
        #print (Upd_stmt)
        SQLitedb.UpdateTable(Upd_stmt)

              

args = sys.argv[1:]
Registry_To_Parse = args[0]
SQLite_DB_Name = args[1]
print ('Amcache is ', str(Registry_To_Parse))
print ('DB file is ', SQLite_DB_Name)
        
SQLitedb = SQLiteDb()
SQLitedb.RemoveDB_File(SQLite_DB_Name)
SQLitedb.Open(SQLite_DB_Name)

SQLitedb.CreateTempTable(table_name_1 + "_Temp", table_col_1)
SQLitedb.CreateTempTable(table_name_2 + "_Temp", table_col_2)
SQLitedb.CreateTempTable(table_name_3 + "_Temp", table_col_3)
SQLitedb.CreateTempTable(table_name_4 + "_Temp", table_col_4)
SQLitedb.CreateTempTable(table_name_5 + "_Temp", table_col_5)

reg = Registry.Registry(Registry_To_Parse)

parse_programs(reg)
parse_files(reg)
parse_orphan(reg)

SQLitedb.CreatePermanentTable(table_name_1, table_name_1 + "_Temp")
SQLitedb.CreatePermanentTable(table_name_2, table_name_2 + "_Temp")
SQLitedb.CreatePermanentTable(table_name_3, table_name_3 + "_Temp")
SQLitedb.CreatePermanentTable(table_name_4, table_name_4 + "_Temp")
SQLitedb.CreatePermanentTable(table_name_5, table_name_5 + "_Temp")

Consolidate_Data()
SQLitedb.Close()