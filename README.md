Burp Notes Extension
January 2013
Austin Lane<alane@trustwave.com>
http://www.trustwave.com

INTRODUCTION
============

Burp Notes Extension is a plugin for Burp Suite that adds a Notes tab. The 
tool aims to better organize external files that are created during 
penetration testing.

Features:
o Create text documents and spreadsheets directly within the Burp interface
o Send HTTP requests and responses directly to new or existing files

REQUIREMENTS
============

Burp Suite Pro 1.5.0.1+
OpenCSV (if building from source) - http://opencsv.sourceforge.net

BUILDING FROM SOURCE
====================

1. Drop Burp Suite Pro and the latest OpenCSV JARs in ./lib
2. ant clean; ant compile; ant jar;

USAGE
=====

In Burp Suite navigate to the Extender tab. 
Select "Add".
Leave Extension Type as "Java" and choose "Select file…".
Navigate to the included "BurpNotesExtension.jar" file or your JAR compiled 
from source, then click "Open".
Click "Next" to load the plugin. 

Within the Notes tab, there are four options:
o Save Notes: Save any currently open documents to a file.
o Load Notes: Load a previously saved set of notes from a file.
o Add Text: Add a tab with a new text document.
o Add Spreadsheet: Add a tab with a new spreadsheet.

From other tabs in Burp, right clicking in areas where a user can normally 
interact with HTTP Responses and Requests, such as the Proxy History or 
Site Map Table, will present options to send those items directly to the 
Notes Tab, either in a new document or appended to an existing one.

COPYRIGHT
=========

Burp Notes Extension - A plugin for Burp Suite that adds text documents and 
spreadsheets.
Austin Lane
Copyright (C) 2013 Trustwave
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
