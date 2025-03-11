# parole
Parole is a password manager using Python and Tkinter (GUI).  It stores data in a single - crypted with a fernet key - file using a user-friendly interface.
<br>This fernet key is hard-coded within parole.py. Keep it secret, and maybe do not keep parole.py and .paz in the same place...

## .paz
<br>Extension of the data file(s) is .paz, on creation of a .paz file, you will be asked for a password.
<br>On opening .paz file, you will be asked for the password.

## To resume
A .paz file will contain all data, it is crypted (fernet-key) and protected by a password.
<br>This way it should be safe as an unkown user, even with the fernet-key, will need the traditionnal password (crypted within the file) to open a .paz file.

## Data
site URL | Site name | User nickname(optionnal) | User connection | User password | Comment(optionnal)
<br>Two buttons: Copy connection | Copy password, to quickly copy/paste these values
<br>Search functionnality

## Dependencies
pip install cryptography pyperclip

## Export
Will export all datas to .json file format
