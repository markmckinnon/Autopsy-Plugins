import os
import sys
import pyolecf
import pylnk
import codecs
from Database import SQLiteDb
import ntpath
import argparse
from JL_App_Ids import JL_App_Ids

table_name = 'Automatic_Destinations_JL'
table_columns = 'File_Name Text, File_Description Text, Item_Name text, command_line_arguments  Text, drive_type Number, drive_serial_number number, ' + \
                'description text, environment_variables_location text, file_access_time text, file_attribute_flags Number, ' + \
                'file_creation_time Text, file_modification_time text, file_size Number, icon_location text, ' + \
                'link_target_identifier_data Text, local_path text, machine_identifier text, network_path Text, ' + \
                'relative_path Text, volume_label text, working_directory text'

sql_ins_columns = 'File_Name, File_Description, Item_Name, command_line_arguments, drive_type, drive_serial_number, description, environment_variables_location, ' + \
                  'file_access_time, file_attribute_flags, file_creation_time, file_modification_time, file_size, icon_location, ' + \
                  'link_target_identifier_data, local_path, machine_identifier, network_path, relative_path, volume_label, ' + \
                  'working_directory'

sql_bind = '?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?'

#def uprint(*objects, sep=' ', end='\n', file=sys.stdout):
#    enc = file.encoding
#    if enc == 'UTF-8':
#        print(*objects, sep=sep, end=end, file=file)
#    else:
#        f = lambda obj: str(obj).encode(enc, errors='backslashreplace').decode(enc)
#        print(*map(f, objects), sep=sep, end=end, file=file)

def get_filepaths(directory):
    """
    This function will generate the file names in a directory 
    tree by walking the tree either top-down or bottom-up. For each 
    directory in the tree rooted at directory top (including top itself), 
    it yields a 3-tuple (dirpath, dirnames, filenames).
    """
    file_paths = []  # List which will store all of the full filepaths.
    dir_paths = []

    # Walk the tree.
    for root, directories, files in os.walk(directory):
        for filename in files:
            # Join the two strings in order to form the full filepath.
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)  # Add it to the list.
            #if '.EVTX' in filepath:
            #file_paths = file_paths + full_file_paths
            #file_paths.append(filepath)  # Add it to the list.
            #file_paths = file_paths + full_file_paths

    return file_paths # Self-explanatory.

def Create_Bind_Values(SQL_Bind_Values, new_link_item):

    if (new_link_item.get_command_line_arguments() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_command_line_arguments())
    if (new_link_item.get_drive_type() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_drive_type())
    if (new_link_item.get_drive_serial_number() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_drive_serial_number())
    if (new_link_item.get_description() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_description())
    if (new_link_item.get_environment_variables_location() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_environment_variables_location())
    SQL_Bind_Values.append(str(new_link_item.get_file_access_time()))
    SQL_Bind_Values.append(str(new_link_item.get_file_attribute_flags()))
    SQL_Bind_Values.append(str(new_link_item.get_file_creation_time()))
    SQL_Bind_Values.append(str(new_link_item.get_file_modification_time()))
    SQL_Bind_Values.append(new_link_item.get_file_size())
    if (new_link_item.get_icon_location() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_icon_location())
    if (new_link_item.get_link_target_identifier_data() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(str(new_link_item.get_link_target_identifier_data()))
    if (new_link_item.get_local_path() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_local_path())
    if (new_link_item.get_machine_identifier() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_machine_identifier())
    if (new_link_item.get_network_path() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_network_path())
    if (new_link_item.get_relative_path() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_relative_path())
    if (new_link_item.get_volume_label() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_volume_label())
    if (new_link_item.get_working_directory() == None):
        SQL_Bind_Values.append('')
    else:
        SQL_Bind_Values.append(new_link_item.get_working_directory())
    return SQL_Bind_Values


def parse_Compound_File(file_to_parse):


    file_object = open(file_to_parse, "rb")
    olecf_file = pyolecf.file()
    olecf_file.open_file_object(file_object)
    SQLitedb.CreateTempTable(table_name + '_temp', table_columns)

    root_item = olecf_file.get_root_item()

    #print ("Root Item Name ==> " + root_item.get_name())
    #print ("Number of Sub_Items ==> " + str(root_item.get_number_of_sub_items()))
    Base_Name = ntpath.basename(file_to_parse)
    (File_Name, Extension) = ntpath.splitext(Base_Name)

    if (App_Id.CheckAppId(File_Name)):
        App_Id_Desc = App_Id.SelectAppId(File_Name)[0]
        #print ("App id => " + App_Id.SelectAppId(File_Name)[0])
    else:
        App_Id_Desc = File_Name
        #print ("File Name => " + File_Name)

    for i in range (0, root_item.get_number_of_sub_items()):
        jl_record = []
        jl_record.append(File_Name)
        jl_record.append(App_Id_Desc)
        new_item = root_item.get_sub_item(i)
        jl_record.append(new_item.get_name())
        #print ("   Sub Item Name ==> " + new_item.get_name())
        #print ("   Sub Item Sub Items ==> " + str(new_item.get_number_of_sub_items()))
        if new_item.get_name() == u'DestList':
            continue
        new_link_item = pylnk.file()
        new_link_item.open_file_object(new_item)
        jl_record = Create_Bind_Values(jl_record, new_link_item)
        try:
            SQLitedb.InsertBindValues(table_name + '_temp', sql_ins_columns, sql_bind, jl_record)
        except:
            print ("Error in Link Item ==> " + str(jl_record[1]) + " <==> " + str(jl_record[2]))
    if (SQLitedb.TableExists(table_name)):
        SQLitedb.AppendTempToPermanentTable(table_name)
    else:
        SQLitedb.CreatePermanentTable(table_name)
    SQLitedb.DropTable(table_name + '_temp')

args = sys.argv[1:]
Directory_To_Parse = args[0]
SQLite_DB_Name = args[1]
App_id_db = args[2]
print ('Dir is ', str(Directory_To_Parse))
print ('DB file is ', SQLite_DB_Name)
App_Id = JL_App_Ids()
App_Id.Open(App_id_db)
#Directory_To_Parse = input('List the directory you want to parse:')   
#File_To_Parse = input("What File do you want to parse: ")
#SQLite_DB_Name = input("What is the Name of the SQLite DB to create: ")
SQLitedb = SQLiteDb()
SQLitedb.Open(SQLite_DB_Name)
# Run the above function and store its results in a variable.   
Full_File_Paths = get_filepaths(Directory_To_Parse)
#Full_File_Paths = get_filepaths(str(sys.argv[0]))
#print (Full_File_Paths)
for files in Full_File_Paths:
    print("File to Process is ==> " + files)
    try:
        if pyolecf.check_file_signature(files):
            print ("Processing File......")
            parse_Compound_File(files)
    except:
        print ("Not a valid compound file ==> " + files)
SQLitedb.Close()  
