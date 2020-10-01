# Secure-password-checker

Checks wherever your password have been hacked.

Check executed by hashing password and passing part of the hash to https://api.pwnedpasswords.com
In responce hash tails of compromised passwords return.<br>

Paswwords can by passed to script by command line parametrs, text file or csv file<br>

Text paramets example:<br>
py password_check.py 123 fvkfmhgf 6778

Text file example:<br>
py password_check.py ./test_files/passwords.txt

CSV file example:<br>
py password_check.py ./test_files/passwords.csv <password_colum_name><br>
optionally password_colum_name could be passed if there is many columns if file.
By default password_colum_name = 'password'


 