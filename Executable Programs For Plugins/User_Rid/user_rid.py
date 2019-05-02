from yarp import RegistryHelpers, Registry
import os
from datetime import datetime
import struct 
import sys

# Create a Dict for the uid and name
userId = {}

def openRegistryFile(primaryPath):

   # A primary file is specified here.
   primary_path = primaryPath
   # Discover transaction log files to be used to recover the primary file, if required.
   transaction_logs = RegistryHelpers.DiscoverLogFiles(primary_path)
   # Open the primary file and each transaction log file discovered.
   primary_file = open(primary_path, 'rb')
   if transaction_logs.log_path is not None:
       log_file = open(transaction_logs.log_path, 'rb')
   else:
       log_file = None
   if transaction_logs.log1_path is not None:
       log1_file = open(transaction_logs.log1_path, 'rb')
   else:
       log1_file = None
   if transaction_logs.log2_path is not None:
       log2_file = open(transaction_logs.log2_path, 'rb')
   else:
       log2_file = None

   # Open the hive and recover it, if required.
   hive = Registry.RegistryHive(primary_file)
   recovery_result = hive.recover_auto(log_file, log1_file, log2_file)
   if recovery_result.recovered:
       print('The hive has been recovered')
   # Print basic information about the hive.
   print('Last written timestamp: {}'.format(hive.last_written_timestamp()))
   print('Last reorganized timestamp: {}'.format(hive.last_reorganized_timestamp()))
   
   return hive
   


def parseSam(pathToRegistry):

   # A primary file is specified here.
   primary_path = os.path.join(pathToRegistry,'SAM')

   # Open the registry file and recover using the transaction logs
   hive = openRegistryFile(primary_path)

   # Find an existing key.
   key = hive.find_key("SAM\\Domains\\Account\\Users")
    
   # Print information about its subkeys.
   for sk in key.subkeys():
       if sk.values_count() > 0:
            registryKey = sk.name()
            skValues = sk.values()
            for skValue in skValues:
               if skValue.name() == 'V':
                   bin_data = skValue.data_raw()
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
                   userId[str(int(registryKey, 16))] = user_name.decode("utf-16")

args = sys.argv[1:]
pathToRegistry = args[0]
csvOutputFile = args[1]
    
now = datetime.now()

print ("Start Script Current date and time : " + str(now.strftime("%Y-%m-%d %H:%M:%S")))

parseSam(pathToRegistry)

with open(csvOutputFile, "w") as file: 
    file.write("RID, USERNAME \n")
    userRecord = []
    userRid = userId.keys()
    for rid in userRid:
        userRec = []
        userRec.append(rid)
        userRec.append(userId[rid])
        userRecord.append(userRec)
    for userRec in userRecord:
        csvOut = ",".join(userRec)
        file.write(csvOut + "\n")
        
#print (userId)
#print (bamRecord)

now = datetime.now()

print ("End Script Current date and time : " + str(now.strftime("%Y-%m-%d %H:%M:%S")))


