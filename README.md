# Mortuus
#### Video Demo:  <URL HERE>
#### Description:
This project is a web app made in flask.
It has been designed for use in funeral homes to keep a digitised record of deceased people currently in care as well as information regarding their funerals.

##### App.py
This is the flask app which controls the website handling logging in and adding, deleting, updating and showing the data stored in the SQLite database.
Intiaily this files ensure the SQLite database has been created if one does not already exist. This includes one table for users logins and passwords and a table to store deceased details.

##### Templates
This file contains the html files which display the website, the most important being index.html which uses Jinja 2 syntax to populate the html table with the deceased details passed from app.py.
index.html also includes some JavaScript to dynamically show a drop down for data entry purposes. I found this was the smoothest way to keep a user on the same page without having to redirect with Flask to add or update.
The updateValues function lets the user edit/update a database entry while seeing the already existing data stored for that entry.
Additionally between app.py and index.html a user can filter and search for deceased using either names or the location (stored as a branch number ie 0182)

##### Static
This file contains the css files for the web app.
To improve visual design bootstrap css and templates have been used to keep everything consistent, more small screen compatible and aesthetically pleasing.


