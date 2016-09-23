# JL_App_Ids.py = Python class for database access of Jump Lists
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
#  Initial Version - April 2016
# 
#Classes to connect, create, read from and write to Jumplist databases.

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

    self._cursor.execute(sql_query)
    if self._cursor.fetchone():
      has_app_id = True
    else:
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