# MySQL_SSE
Local implementation of Symmetric Searchable Encryption using Python and MySQL

# How to Run
1. Have Python 3 and Pip installed
2. Install dependencies mysql-connector-python and pycryptodome with Pip
```
pip install mysql-connector-python
```
```
pip install pycryptodome
```
3. Have an empty local MySQL database configured. If you are not familiar with MySQL or SQL, this article should
explain the setup process: https://dev.mysql.com/doc/mysql-getting-started/en/

4. To run the program, navigate to the folder where program files are located with terminal and type:
```
python3 mysql_sse.py
```
5. The program will ask for your MySQL credentials in order to connect to the database
6. On the first run, enter command "CT" in the UI to create the MySQL tables
7. Use "IF" to input files
8. Use "S" to search for certain keywords
