REM This is a sample insert into the database of a Extracted content SQL
REM Make sure the where clause is the only thing that is changed in the SQL statement
REM Do not add a semicolon (;) at the end of the SQL statement as we have to add
REM   something else in the plugin code to make sure it gets attributed to the correct
REM   fsevents file in the extracted content for each one.

insert into extracted_content_sql values 
("select filename, mask, source, case other_dates when 'UNKNOWN' then NULL else other_dates end 'OTHER_DATES' from fsevents WHERE filename LIKE 'Users/%/Library/Caches/Metadata/Safari/History/%' OR filename LIKE 'Users/%/Library/Application Support/Google/Chrome/Default/Local Storage/%' OR filename LIKE 'Users/%/Library/Safari/LocalStorage/%' ",
 "TSK_MACOS_INTERNET_BROWSER_ACT_FSEVENTS", "Internet Browser Activity FSEvents");