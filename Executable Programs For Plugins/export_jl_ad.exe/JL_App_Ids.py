import sqlite3
import os
import sys

class JL_App_Ids(object):
  #Class that defines a sqlite3 database file.

  def __init__(self):
    """Initializes the database file object."""
    super(JL_App_Ids, self).__init__()
    self._connection = None
    self._cursor = None
    self.filename = 'Jump_List_App_Ids.db3'
    self.read_only = None
	
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
    #self.filename = None
    self.read_only = None

  def CheckAppId (self, App_Id):
    # Checks if the table exists in the database

    # Args:
    #  sql_query: query you want to execute.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.

    if not self._connection:
      raise RuntimeError(
          u'Cannot determine if table exists database not opened.')

    sql_query = "Select AppID, App_Desc, Date_Added, source from application_ids Where upper(AppID) = Upper('" + App_Id + "');"

    try:
        self._cursor.execute(sql_query)
        if self._cursor.fetchone():
          has_app_id = True
        else:
          has_app_id = False
    except:
        has_app_id = False

    return has_app_id

  def SelectAppId (self, App_Id):
    # Checks if the table exists in the database

    # Args:
    #  sql_query: query you want to execute.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.

    if not self._connection:
      raise RuntimeError(
          u'Cannot determine if table exists database not opened.')

    sql_query = "Select App_Desc from application_ids Where upper(AppID) = upper('" + App_Id + "');"

    self._cursor.execute(sql_query)
    return self._cursor.fetchone()

  def SelectAllAppIds (self):
    # Checks if the table exists in the database

    # Args:
    #  sql_query: query you want to execute.

    #Raises:
    #  RuntimeError: if the database is not opened or
    #                if the database is in read-only mode.

    if not self._connection:
      raise RuntimeError(
          u'Cannot determine if table exists database not opened.')

    sql_query = 'Select AppID, App_Desc, Date_Added, source from application_ids;'
	
    self._cursor.execute(sql_query)
    return self._cursor.fetchall()

  def Open(self, file_name, read_only=False):
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

    #self.filename = filename
    self.read_only = read_only

    self._connection = sqlite3.connect(file_name)
    if not self._connection:
      return False

    self._cursor = self._connection.cursor()
    if not self._cursor:
      return False

    return True