import os
import sys
import pyregf
import codecs
import struct
from Database import SQLiteDb
import datetime


acct_type_dict = {188 : "Default Admin User", 212 : "Custom Limited Acct", 176 : "Default Guest Acct", 268 : " "}
acb_flags_dict = {1 : "Account Disabled", 2 : "Home directory required", 4 : "Password not required", 8 : "Temporary duplicate account", + \
             16 : "Normal user account", 32 : "MNS logon user account", 64 : "Interdomain trust account", 128 : "Workstation trust account", + \
             256 : "Server trust account", 512 : "Password does not expire", 1024 : "Account auto locked"}

table_name = 'Sam'
table_columns = 'User_Name text, Full_Name text, Comment text, Name text, Internet_UserName text, Password_Hint text, Account_Type text, ' + \
                'Create_dttm text, Last_Login_Date text, Pwd_Reset_Date text, Acct_Exp_Date text, Pwd_Fail_Date text, User_rid text, '\
                'User_ACB_FLAGS text, User_failed_COunt number, User_login_count number, user_acb_desc text'
sql_ins_columns = 'User_Name, Full_Name, Comment, Name, Internet_UserName, Password_Hint, Account_Type, Create_dttm, Last_Login_Date, ' + \
                  'Pwd_Reset_Date, Acct_Exp_Date, Pwd_Fail_Date, User_rid, User_ACB_FLAGS, User_failed_COunt, User_login_count, user_acb_desc' 
sql_bind = '?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?'

def uprint(*objects, sep=' ', end='\n', file=sys.stdout):
    enc = file.encoding
    if enc == 'UTF-8':
        print(*objects, sep=sep, end=end, file=file)
    else:
        f = lambda obj: str(obj).encode(enc, errors='backslashreplace').decode(enc)
        print(*map(f, objects), sep=sep, end=end, file=file)

		
def parse_registry_file(file_to_parse):

   
   file_object = open(file_to_parse, "rb")
   reg_file = pyregf.file()
   reg_file.open_file_object(file_object)
   #SQLitedb.CreateTempTable(table_name + '_temp', table_columns)
#   key_path = reg_file.get_key_by_path("SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
#   key_path = reg_file.get_key_by_path("SAM\\Domains\\Account\\Users\\Names")
   key_path = reg_file.get_key_by_path("SAM\\Domains\\Account\\Users")
   
   print ("Number of Sub_Keys ==> ", key_path.get_number_of_sub_keys())
   print ("Number of values ==> ", key_path.get_number_of_values())
   
   for i in range (0, key_path.get_number_of_sub_keys() - 1):
      sub_key = key_path.get_sub_key(i)
      user_key = sub_key.get_value_by_name("V")
      if (user_key.get_type() == 3):
          bin_data = user_key.get_data()
          acct_type_number = int(str(struct.unpack_from('<l', bin_data[4:])[0]))
          #print (acct_type_number)
          if acct_type_number in acct_type_dict:
             account_type = acct_type_dict[acct_type_number]
          else:
             account_type = 'Unknown Acct Type'
          pos_1 = int(str(struct.unpack_from('<l', bin_data[4:])[0]))
          pos_3 = int(str(struct.unpack_from('<l', bin_data[12:])[0])) + 204 
          pos_4 = int(str(struct.unpack_from('<l', bin_data[16:])[0]))
          pos_6 = int(str(struct.unpack_from('<l', bin_data[24:])[0])) + 204
          pos_7 = int(str(struct.unpack_from('<l', bin_data[28:])[0]))
          pos_9 = int(str(struct.unpack_from('<l', bin_data[36:])[0])) + 204
          pos_10 = int(str(struct.unpack_from('<l', bin_data[40:])[0]))
          fmt_string_name = ">" + str(pos_4) + "s"		  
          fmt_string_fullname = ">" + str(pos_7) + "s"
          fmt_string_comment = ">" + str(pos_10) + "s"
          user_name = struct.unpack_from(fmt_string_name, bin_data[pos_3:])[0]
          full_name = struct.unpack_from(fmt_string_fullname, bin_data[pos_6:])[0]
          comment = struct.unpack_from(fmt_string_comment, bin_data[pos_9:])[0]
      elif (user_key.get_type() == 1):
          print ("Data of Key ==> ", user_key.get_data_as_string())

      key_path_name = reg_file.get_key_by_path("SAM\\Domains\\Account\\Users\\Names\\" + str(user_name.decode("utf-16")))
      user_name_create_dttm = key_path_name.get_last_written_time()
	  
      user_key = sub_key.get_value_by_name("F")
      if (user_key.get_type() == 3):
          bin_data = user_key.get_data()
          last_login_date = int(str(struct.unpack_from('<q', bin_data[8:])[0])[0:11]) - 11644473600
          pwd_reset_date = int(str(struct.unpack_from('<q', bin_data[24:])[0])[0:11]) - 11644473600
          acct_exp_date = int(str(struct.unpack_from('<q', bin_data[32:])[0])[0:11]) - 11644473600
          pwd_fail_date = int(str(struct.unpack_from('<q', bin_data[40:])[0])[0:11]) - 11644473600
          if last_login_date < 0:
             last_login_date = 0
          if pwd_reset_date < 0:
             pwd_reset_date = 0
          if acct_exp_date < 0:
             acct_exp_date = 0
          if pwd_fail_date < 0:
             pwd_fail_date = 0
          user_rid = struct.unpack_from('<l', bin_data[48:])[0]
          user_acb_flags = int(str(struct.unpack_from('<l', bin_data[56:])[0]))
          user_failed_count = int(str(struct.unpack_from('<h', bin_data[64:])[0]))
          user_login_count = int(str(struct.unpack_from('<h', bin_data[66:])[0]))
      elif (user_key.get_type() == 1):
          print ("Data of Key ==> ", user_key.get_data_as_string())

      user_key = sub_key.get_value_by_name("GivenName")
      if user_key == None:
          given_name = "None"
      else:
          bin_data = user_key.get_data()
          fmt_given_name = ">" + str(len(bin_data)) + "s"		  
          given_name = struct.unpack_from(fmt_given_name, bin_data[0:])[0]

      user_key = sub_key.get_value_by_name("SurName")
      if user_key == None:
         sur_name = "None"
      else:
         bin_data = user_key.get_data()
         fmt_sur_name = ">" + str(len(bin_data)) + "s"		  
         sur_name = struct.unpack_from(fmt_sur_name, bin_data[0:])[0]

      user_key = sub_key.get_value_by_name("InternetUserName")
      if user_key == None:
         internet_name = "None"
      else:
         bin_data = user_key.get_data()
         fmt_internet_name = ">" + str(len(bin_data)) + "s"		  
         internet_name = struct.unpack_from(fmt_internet_name, bin_data[0:])[0]

      user_key = sub_key.get_value_by_name("UserPasswordHint")
      if user_key == None:
         pw_hint = "None"
      else:
         bin_data = user_key.get_data()
         fmt_pw_hint = ">" + str(len(bin_data)) + "s"		  
         pw_hint = struct.unpack_from(fmt_pw_hint, bin_data[0:])[0]

      try:
         # print ("==============================================================")
         # print (" User Name ==> ", str(user_name.decode("utf-16")))
         # print (" Full Name ==> ", str(full_name.decode("utf-16")))
         # print (" Comment ==> ", str(comment.decode("utf-16")))
         # if sur_name == "None" or given_name == "None":
            # print (" Name ==> ", sur_name, " ", given_name)
         # else:
            # print (" Name ==> ", str(sur_name.decode("utf-16")), " ", str(given_name.decode("utf-16")))
         # if internet_name == "None":
            # print (" Internet Username ==> ", internet_name)
         # else:
            # print (" Internet UserName ==> ", str(internet_name.decode("utf-16")))
         # if pw_hint == "None":
            # print (" Password Hint ==> ", pw_hint)
         # else:
            # print (" Password Hint ==> ", str(pw_hint.decode("utf-16")))
         # print (" Account Type ==> ", account_type)
         # print (" Create_dttm ==> ", str(user_name_create_dttm))
         # print (" Last_Login_Date ==> ", datetime.datetime.fromtimestamp(last_login_date).strftime('%Y-%m-%d %H:%M:%S'))
         # print (" Pwd_Reset_Date ==> ", datetime.datetime.fromtimestamp(pwd_reset_date).strftime('%Y-%m-%d %H:%M:%S'))
         # if acct_exp_date == 0 or acct_exp_date == 80589246768:
            # print (" Acct_Exp_Date ==> No Expire Date")
         # else:
            # print (" Acct_Exp_Date ==> ", datetime.datetime.fromtimestamp(acct_exp_date).strftime('%Y-%m-%d %H:%M:%S'))
         # if pwd_fail_date == 0:
            # print (" Pwd_Fail_Date ==> No Fail Date")
         # else:
            # print (" Pwd_Fail_Date ==> ", datetime.datetime.fromtimestamp(pwd_fail_date).strftime('%Y-%m-%d %H:%M:%S'))
         # print (" User_rid ==> ", user_rid)
         # print (" User_ACB_FLAGS ==> ", user_acb_flags)
         # print (" User failed COunt ==> ", user_failed_count)
         # print (" User login count ==> ", user_login_count)
         # for x in acb_flags_dict:
            # if ( x & user_acb_flags):
                # print ("  ----> ", acb_flags_dict[x])
         # print ("==============================================================")
         sql_val_columns = []
         sql_val_columns.append(str(user_name.decode("utf-16")))
         sql_val_columns.append(str(full_name.decode("utf-16")))
         sql_val_columns.append(str(comment.decode("utf-16")))
         if sur_name == "None" or given_name == "None":
            sql_val_columns.append("")
         else:
            sql_val_columns.append(str(sur_name.decode("utf-16")) + " " + str(given_name.decode("utf-16")))
         if internet_name == "None":
            sql_val_columns.append("")
         else:
            sql_val_columns.append(str(internet_name.decode("utf-16")))
         if pw_hint == "None":
            sql_val_columns.append("")
         else:
            sql_val_columns.append(str(pw_hint.decode("utf-16")))
         sql_val_columns.append(account_type)
         sql_val_columns.append(str(user_name_create_dttm))
         sql_val_columns.append(datetime.datetime.fromtimestamp(last_login_date).strftime('%Y-%m-%d %H:%M:%S'))
         sql_val_columns.append(datetime.datetime.fromtimestamp(pwd_reset_date).strftime('%Y-%m-%d %H:%M:%S'))
         if acct_exp_date == 0 or acct_exp_date == 80589246768:
            sql_val_columns.append("")
         else:
            sql_val_columns.append(datetime.datetime.fromtimestamp(acct_exp_date).strftime('%Y-%m-%d %H:%M:%S'))
         if pwd_fail_date == 0:
            sql_val_columns.append("No Fail Date")
         else:
            sql_val_columns.append(datetime.datetime.fromtimestamp(pwd_fail_date).strftime('%Y-%m-%d %H:%M:%S'))
         sql_val_columns.append(user_rid)
         sql_val_columns.append(user_acb_flags)
         sql_val_columns.append(user_failed_count)
         sql_val_columns.append(user_login_count)
         acb_desc = ""
         for x in acb_flags_dict:
            if ( x & user_acb_flags):
                acb_desc = acb_desc + acb_flags_dict[x] + "\n"
         sql_val_columns.append(acb_desc)
         SQLitedb.InsertBindValues(table_name, sql_ins_columns, sql_bind, sql_val_columns)
      except:
         print ("Bad Character")		  
	  

args = sys.argv[1:]
Registry_To_Parse = args[0]
SQLite_DB_Name = args[1]
print ('Registry is ', str(Registry_To_Parse))
print ('DB file is ', SQLite_DB_Name)
#Directory_To_Parse = input('List the directory you want to parse:')   
#File_To_Parse = input("What File do you want to parse: ")
#SQLite_DB_Name = input("What is the Name of the SQLite DB to create: ")

#SQLite_DB_Name = "Test1.db3"
#registry_file = "sam"
SQLitedb = SQLiteDb()
SQLitedb.RemoveDB_File(SQLite_DB_Name)
SQLitedb.Open(SQLite_DB_Name)
SQLitedb.CreateTable(table_name, table_columns)

parse_registry_file(Registry_To_Parse)

SQLitedb.Close()  

