Rem
Rem Create table statements
Rem

CREATE TABLE Art_Att_Mac_Xref
(mac_osx_art_id number,
 autopsy_art_id number,
 autopsy_attrib_id number);

CREATE TABLE OS_Version
(OS_id number,
 OS_Version text,
 OS_Name text);

CREATE TABLE autopsy_artifact
 (autopsy_art_id number,
  autopsy_art_type text,
  autopsy_art_name text,
  autopsy_art_description text);

CREATE TABLE autopsy_attribute
( autopsy_attrib_id number,
  autopsy_attrib_type text,
  Autopsy_attrib_name text,
  Autopsy_attrib_desc text,
  Autopsy_attrib_value_type number);

CREATE TABLE autopsy_value_type
(Autopsy_attrib_value_type number,
 Autopsy_attrib_value_type_desc text);

CREATE TABLE mac_artifact 
(mac_osx_art_id number,
 mac_osx_art_Type text,
 mac_osx_art_File_name text,
 mac_osx_art_Dir_Name text,
 mac_osx_art_Exec_File text,
 mac_osx_art_database_name text,
 mac_osx_art_table_name text,
 mac_osx_art_sql_statement text,
 OS_id number,
 system_user_artifact text);

 
Rem
Rem Code table data
Rem
  
insert into AUtopsy_value_type values (0, 'String');
insert into Autopsy_value_type values (1, 'Integer');
insert into Autopsy_value_type values (2, 'Long');
insert into Autopsy_value_type values (3, 'Double');
insert into Autopsy_value_type values (4, 'Byte');
insert into Autopsy_value_type values (5, 'DateTime');
 
insert into OS_Version values (1, '10.6',  'Snow Leopard');
insert into OS_Version values (2, '10.7', 'Lion');
insert into OS_Version values (3, '10.8', 'Mountain Lion');
insert into OS_Version values (4, '10.9', 'Mavericks');
insert into OS_Version values (5, '10.10', 'Yosemite');
insert into OS_Version values (6, '10.11', 'El Capitan');
insert into OS_Version values (7, '10.12', 'Sierra');
Insert into OS_Version values (0, 'All', 'All');
 
Rem
Rem Artifact Data
Rem

insert into mac_artifact values
(1, 'Plist', 'SystemVersion.plist','/System/Library/CoreServices','plist_db.exe','SystemVersion','SystemVersion.db3',
 "Select a.value 'TSK_MAC_BUILD_VERSION', b.value 'TSK_VERSION', c.value 'TSK_NAME' from plists a, plists b, plists c where a.name = '\ProductBuildVersion' and b.name = '\ProductVersion' and c.name = '\ProductName'", 0,'SYSTEM');
insert into mac_artifact values
(2, 'Plist','InstallHistory.plist','/Library/Receipts','plist_db.exe','InstallHistory',
 'installhistory.db3',
 "select DisplayVersion 'TSK_PROGRAM_DISPLAY_VERSION', DisplayName 'TSK_PROG_NAME', Date 'TSK_DATETIME', processname 'TSK_PROG_HOW_INSTALLED' from installhistory", 7, 'SYSTEM');
insert into mac_artifact values
(3, 'SQLite','Accounts4.sqlite','/Library/Accounts', NULL, 'Accounts4.sqlite', Null,
 "select zaccounttypedescription 'TSK_ACCOUNT_TYPE', a.zcredentialtype 'TSK_CREDENTIAL_TYPE', a.Zidentifier 'TSK_ACCOUNT_IDENTIFIER', strftime('%s', datetime(zdate + 978307200,'unixepoch')) 'TSK_DATETIME', zaccountdescription 'TSK_ACCOUNT_DESCRIPTION', zusername 'TSK_USER_NAME' from zaccounttype a, zaccount b where a.z_pk = b.zaccounttype;", 7, 'USER');
 
insert into autopsy_artifact values 
 (1, 'AUTOPSY', 'TSK_OS_INFO', null);
insert into autopsy_artifact values 
 (2, 'AUTOPSY', 'TSK_INSTALLED_PROG', null);
insert into autopsy_artifact values 
 (3, 'AUTOPSY', 'TSK_ACCOUNT', null);

insert into autopsy_attribute values (1, 'CUSTOM', 'TSK_MAC_BUILD_VERSION','MAC Build Version', 0);
insert into autopsy_attribute values (2, 'AUTOPSY', 'TSK_VERSION', NULL, 0);
insert into autopsy_attribute values (3, 'AUTOPSY', 'TSK_NAME', NULL, 0);
insert into autopsy_attribute values (4, 'AUTOPSY','TSK_PROG_NAME',null, 0);
insert into autopsy_attribute values (5, 'AUTOPSY','TSK_DATETIME',null, 5);
insert into autopsy_attribute values (6, 'CUSTOM','TSK_PROG_HOW_INSTALLED','Installation Method', 0);
insert into Autopsy_attribute values (7, 'CUSTOM', 'TSK_PROGRAM_DISPLAY_VERSION', 'Display Version', 0)
insert into Autopsy_attribute values (8, 'AUTOPSY', 'TSK_ACOUNT_TYPE', NULL, 0)
insert into Autopsy_attribute values (9, 'CUSTOM', 'TSK_CREDENTIAL_TYPE', 'Credential Type', 0)
insert into Autopsy_attribute values (10, 'CUSTOM', 'TSK_ACCOUNT_IDENTIFIER', 'Account Identifier', 0)
insert into Autopsy_attribute values (11, 'CUSTOM', 'TSK_ACCOUNT_DESCRIPTION', 'Account Description', 0)
insert into Autopsy_attribute values (12, 'AUTOPSY', 'TSK_USER_NAME', NULL, 0)

insert into Art_Att_Mac_Xref values (1, 1, 1);
insert into Art_Att_Mac_Xref values (1, 1, 2);
insert into Art_Att_Mac_Xref values (1, 1, 3);
insert into Art_Att_Mac_Xref values (2, 2, 4);
insert into Art_Att_Mac_Xref values (2, 2, 5);
insert into Art_Att_Mac_Xref values (2, 2, 6);
insert into Art_Att_Mac_Xref values (2, 2, 7);
insert into Art_Att_Mac_Xref values (3, 3, 8);
insert into Art_Att_Mac_Xref values (3, 3, 9);
insert into Art_Att_Mac_Xref values (3, 3, 10);
insert into Art_Att_Mac_Xref values (3, 3, 5);
insert into Art_Att_Mac_Xref values (3, 3, 11);
insert into Art_Att_Mac_Xref values (3, 3, 12);
 
REM
REM New Artifacts Accounts3.sqlite - El Capitan
REM

insert into mac_artifact values
(4, 'SQLite','Accounts3.sqlite','/Library/Accounts', NULL, 'Accounts3.sqlite', Null,
 "select zaccounttypedescription 'TSK_ACCOUNT_TYPE', a.zcredentialtype 'TSK_CREDENTIAL_TYPE', a.Zidentifier 'TSK_ACCOUNT_IDENTIFIER', strftime('%s', datetime(zdate + 978307200,'unixepoch')) 'TSK_DATETIME', zaccountdescription 'TSK_ACCOUNT_DESCRIPTION', zusername 'TSK_USER_NAME' from zaccounttype a, zaccount b where a.z_pk = b.zaccounttype;", 6, 'USER');

insert into Art_Att_Mac_Xref values (4, 3, 8);
insert into Art_Att_Mac_Xref values (4, 3, 9);
insert into Art_Att_Mac_Xref values (4, 3, 10);
insert into Art_Att_Mac_Xref values (4, 3, 5);
insert into Art_Att_Mac_Xref values (4, 3, 11);
insert into Art_Att_Mac_Xref values (4, 3, 12);
 
REM
REM   New Mounted Volumes - All versions
REM
 
insert into mac_artifact values
(5, 'Plist','com.apple.sidebarlists.plist','/Library/Preferences', 'plist2db.exe', 'sidebarlists.db3', Null,
 "Select value 'TSK_MAC_MOUNTED_VOLUME' from plists where name = '\systemitems\VolumesList\Name'", 7, 'USER');
insert into mac_artifact values
(6, 'Plist','com.apple.sidebarlists.plist','/Library/Preferences', 'plist2db.exe', 'sidebarlists.db3', Null,
 "Select value 'TSK_MAC_MOUNTED_VOLUME' from plists where name = '\systemitems\VolumesList\Name'", 6, 'USER');
insert into mac_artifact values
(7, 'Plist','com.apple.sidebarlists.plist','/Library/Preferences', 'plist2db.exe', 'sidebarlists.db3', Null,
 "Select value 'TSK_MAC_MOUNTED_VOLUME' from plists where name = '\systemitems\VolumesList\Name'", 5, 'USER');
insert into mac_artifact values
(8, 'Plist','com.apple.sidebarlists.plist','/Library/Preferences', 'plist2db.exe', 'sidebarlists.db3', Null,
 "Select value 'TSK_MAC_MOUNTED_VOLUME' from plists where name = '\systemitems\VolumesList\Name'", 4, 'USER');


insert into autopsy_attribute values (13, 'CUSTOM', 'TSK_MAC_MOUNTED_VOLUME','MAC Mounted Volume', 0);

insert into autopsy_artifact values 
 (4, 'CUSTOM', 'TSK_MACOS_MOUNTED_VOLUMES', 'MacOS Mounted Volumes');

insert into Art_Att_Mac_Xref values (5, 4, 13);
insert into Art_Att_Mac_Xref values (6, 4, 13);
insert into Art_Att_Mac_Xref values (7, 4, 13);
insert into Art_Att_Mac_Xref values (8, 4, 13);
 