#Classes to connect, create, read from and write to SQLite databases.

import os
import re
import sqlite3

class SQLiteDb(object):
  #Class that defines a sqlite3 database file.

  def __init__(self):
    """Initializes the database file object."""
    super(SQLiteDb, self).__init__()
    self._connection = None
    self._cursor = None
    self.filename = None
    self.read_only = None
    self.reserved_word_list_dict = {'ABORT':0, 'ACTION':0, 'ADD':0, 'AFTER':0, 'ALL':0, 'ALTER':0, 'ANALYZE':0, 'AND':0, 'AS':0, 'ASC':0, \
                                    'ATTACH':0, 'AUTOINCREMENT':0, 'BEFORE':0, 'BEGIN':0, 'BETWEEN':0, 'BY':0, 'CASCADE':0, 'CASE':0, \
                                    'CAST':0, 'CHECK':0, 'COLLATE':0, 'COLUMN':0, 'COMMIT':0, 'CONFLICT':0, 'CONSTRAINT':0, 'CREATE':0, \
                                    'CROSS':0, 'CURRENT_DATE':0, 'CURRENT_TIME':0, 'CURRENT_TIMESTAMP':0, 'DATABASE':0, 'DEFAULT':0, \
                                    'DEFERRABLE':0, 'DEFERRED':0, 'DELETE':0, 'DESC':0, 'DETACH':0, 'DISTINCT':0, 'DROP':0, 'EACH':0, \
                                    'ELSE':0, 'END':0, 'ESCAPE':0, 'EXCEPT':0, 'EXCLUSIVE':0, 'EXISTS':0, 'EXPLAIN':0, 'FAIL':0, 'FOR':0, \
                                    'FOREIGN':0, 'FROM':0, 'FULL':0, 'GLOB':0, 'GROUP':0, 'HAVING':0, 'IF':0, 'IGNORE':0, 'IMMEDIATE':0, \
                                    'IN':0, 'INDEX':0, 'INDEXED':0, 'INITIALLY':0, 'INNER':0, 'INSERT':0, 'INSTEAD':0, 'INTERSECT':0, 'INTO':0, \
                                    'IS':0, 'ISNULL':0, 'JOIN':0, 'KEY':0, 'LEFT':0, 'LIKE':0, 'LIMIT':0, 'MATCH':0, 'NATURAL':0, 'NO':0, \
                                    'NOT':0, 'NOTNULL':0, 'NULL':0, 'OF':0, 'OFFSET':0, 'ON':0, 'OR':0, 'ORDER':0, 'OUTER':0, 'PLAN':0, \
                                    'PRAGMA':0, 'PRIMARY':0, 'QUERY':0, 'RAISE':0, 'RECURSIVE':0, 'REFERENCES':0, 'REGEXP':0, 'REINDEX':0, \
                                    'RELEASE':0, 'RENAME':0, 'REPLACE':0, 'RESTRICT':0, 'RIGHT':0, 'ROLLBACK':0, 'ROW':0, 'SAVEPOINT':0, \
                                    'SELECT':0, 'SET':0, 'TABLE':0, 'TEMP':0, 'TEMPORARY':0, 'THEN':0, 'TO':0, 'TRANSACTION':0, 'TRIGGER':0, \
                                    'UNION':0, 'UNIQUE':0, 'UPDATE':0, 'USING':0, 'VACUUM':0, 'VALUES':0, 'VIEW':0, 'VIRTUAL':0, 'WHEN':0, \
                                    'WHERE':0, 'WITH':0, 'WITHOUT':0}


  def RemoveDB_File(self, file_name):
    #removes the database file if it exists
    #
    #Args:
    #  file_name: the name of the file to delete.

    if os.path.isfile(file_name):
        os.remove(file_name)
	
  def Check_SQL_Reserved_Word(self, column_name):
    #Checks to see of the column name would be a reserved word or starts with a number, if it is then put quotes around it
    #
    #Args:
    #  column_name: the column of a table.

    check_key = column_name.upper()
    if check_key in self.reserved_word_list_dict or column_name[0].isdigit():
       return "'" + column_name + "'"
    else:
       return column_name	


  def create_question_bind_variables(self, number_of_columns):
    #Checks to see of the column name would be a reserved word or starts with a number, if it is then put quotes around it
    #
    #Args:
    #  number_of_columns: the number of columns of bind variables.
	
    bind_variables = " ?"
    for i in range(1, number_of_columns):
       bind_variables = bind_variables + ", ?"
    #bind_variables = bind_variables + ")"	   
    return bind_variables
	
  def Close(self):
    #Closes the database file.
    #
    #Raises:
    #  RuntimeError: if the database is not opened.
       
    if not self._connection:
      raise RuntimeError(u'Cannot close database not opened.')

    # We need to run commit or not all data is stored in the database.
    self._connection.commit()
    self._connection.close()

    self._connection = None
    self._cursor = None
    self.filename = None
    self.read_only = None

  def CreateTable(self, table_name, column_definitions):
    #Creates a table.
    #
    #Args:
    #  table_name: the table name.
    #  column_definitions: list of strings containing column definitions.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.
    
    if not self._connection:
      raise RuntimeError(u'Cannot create table database not opened.')

    if self.read_only:
      raise RuntimeError(u'Cannot create table database in read-only mode.')

    sql_query = u'CREATE TABLE {0:s} ( {1:s} )'.format(
        table_name, column_definitions)
 
    #print (sql_query)
 
    self._cursor.execute(sql_query)

  def CreatePermanentTable(self, table_name):
    #Creates a table.
    #
    #Args:
    #  table_name: the table name.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.

    if not self._connection:
      raise RuntimeError(u'Cannot create table database not opened.')

    if self.read_only:
      raise RuntimeError(u'Cannot create table database in read-only mode.')

    sql_query = 'Create Table '+ table_name + ' as select * from ' + table_name + '_Temp;'

    #print (sql_query)
	
    self._cursor.execute(sql_query)

  def CreateTempTable(self, table_name, column_definitions):
    #Creates a table.
    #
    #Args:
    #  table_name: the table name.
    #  column_definitions: list of strings containing column definitions.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.
    
    if not self._connection:
      raise RuntimeError(u'Cannot create table database not opened.')

    if self.read_only:
      raise RuntimeError(u'Cannot create table database in read-only mode.')

    sql_query = u'CREATE Temp TABLE If Not Exists {0:s} ( {1:s} )'.format(
        table_name, column_definitions)

    self._cursor.execute(sql_query)

  def AppendTempToPermanentTable(self, table_name):
    #Creates a table.
    #
    #Args:
    #  table_name: the table name.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.

    if not self._connection:
      raise RuntimeError(u'Cannot create table database not opened.')

    if self.read_only:
      raise RuntimeError(u'Cannot create table database in read-only mode.')

    sql_query = 'insert into '+ table_name + ' select * from ' + table_name + '_Temp;'

    #print (sql_query)
	
    self._cursor.execute(sql_query)

  def AddColumn(self, table_name, column_definitions):
    #Creates a table.
    #
    #Args:
    #  table_name: the table name.
    #  column_definitions: list of strings containing column definitions.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.
    
    if not self._connection:
      raise RuntimeError(u'Cannot create table database not opened.')

    if self.read_only:
      raise RuntimeError(u'Cannot create table database in read-only mode.')

    sql_query = u'Alter TABLE {0:s} Add {1:s} '.format(
        table_name, column_definitions)

    self._cursor.execute(sql_query)

  def DropTable(self, table_name):
    #Creates a table.
    #
    #Args:
    #  table_name: the table name to drop

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.
    
    if not self._connection:
      raise RuntimeError(u'Cannot create table database not opened.')

    if self.read_only:
      raise RuntimeError(u'Cannot create table database in read-only mode.')

    sql_query = u'Drop TABLE {0:s} '.format(
        table_name)

    self._cursor.execute(sql_query)

  def InsertValues(self, table_name, column_definitions, column_bind_values):
    #Inserts values into a table.
    #
    #Args:
    #  table_name: the table name.
    #  column_definitions: list of strings containing column.
    #  column_values: the values to actually inserted

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.
    
    if not self._connection:
      raise RuntimeError(u'Cannot create table database not opened.')

    if self.read_only:
      raise RuntimeError(u'Cannot create table database in read-only mode.')

    sql_query = u'insert into {0:s} ( {1:s} ) values ( {2:s} )'.format(
        table_name, column_definitions, column_bind_values)

    self._cursor.execute(sql_query)

  def InsertBindValues(self, table_name, column_definitions, column_bind_values, column_values):
    #Inserts values into a table.
    #
    #Args:
    #  table_name: the table name.
    #  column_definitions: list of strings containing column.
    #  column_values: the values to actually inserted

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.
    
    if not self._connection:
      raise RuntimeError(u'Cannot create table database not opened.')

    if self.read_only:
      raise RuntimeError(u'Cannot create table database in read-only mode.')

    sql_query = u'insert into {0:s} ( {1:s} ) values ( {2:s} )'.format(
        table_name, column_definitions, column_bind_values)

    #print (sql_query)
	
    self._cursor.execute(sql_query, column_values)

  def TableExists(self, table_name):
    # Checks if the table exists in the database

    # Args:
    #  table_name: the table name.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.

    if not self._connection:
      raise RuntimeError(
          u'Cannot determine if table exists database not opened.')

    sql_query = u'SELECT name FROM sqlite_master WHERE type = "table" AND name = "{0:s}"'.format(table_name)

    self._cursor.execute(sql_query)
    if self._cursor.fetchone():
      has_table = True
    else:
      has_table = False
    return has_table
	
  def SelectOneRow (self, sql_query):
    # Checks if the table exists in the database

    # Args:
    #  sql_query: query you want to execute.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.

    if not self._connection:
      raise RuntimeError(
          u'Cannot determine if table exists database not opened.')

    self._cursor.execute(sql_query)
    return self._cursor.fetchone()

  def SelectAllRows (self, sql_query):
    # Checks if the table exists in the database

    # Args:
    #  sql_query: query you want to execute.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.

    if not self._connection:
      raise RuntimeError(
          u'Cannot determine if table exists database not opened.')

    self._cursor.execute(sql_query)
    return self._cursor.fetchall()

  def Open(self, filename, read_only=False):
    #Opens the database file.

    #Args:
    #  filename: the filename of the database.
    #  read_only: optional boolean value to indicate the database should be
    #             opened in read-only mode. The default is false. Since sqlite3
    #             does not support a real read-only mode we fake it by only
    #             permitting SELECT queries.

    #Returns:
    #  A boolean containing True if successful or False if not.

    #Raises:
    #  RuntimeError: if the database is already opened.
     
    if self._connection:
      raise RuntimeError(u'Cannot open database already opened.')

    self.filename = filename
    self.read_only = read_only

    self._connection = sqlite3.connect(filename)
    if not self._connection:
      return False

    self._cursor = self._connection.cursor()
    if not self._cursor:
      return False

    return True
