import base64
import time
from os import cpu_count
from getpass import getpass
from mysql.connector import connect, Error
from time import perf_counter
from pathlib import Path
from hashlib import sha256
import multiprocessing
from Crypto.Cipher import AES
from Crypto import Random
import sys

import helper_funcs_ctr
import db_funcs

"""
Local DSSE implementation with forward privacy. Uses MySQL as the database.
Encryption/decryption is done with AES256 while using CTR as the mode of operation.

Description:
Program has ability to;  1. Read and index .txt files to implement local SSE scheme
                         2. Search for wanted keyword from the local database and return files containing it
                         3. Display info about database or modify it

TODO: -Implement Delete
      -Implement Modify
      -More strict/efficient stopword remover
"""


def delete(args):
    """
    Deletes a file and all connections to it from the computer and the database
    :param args: MySQL connection object
    :return: None
    """
    pass


def modify(args):
    """
    Modifies a file and updates it's connections in computer and the database
    :param args: MySQL connection object
    :return: None
    """
    pass


def search(args):
    """
    Searches the database for files containing the desired keyword
    :param args: MySQL connection object
    :return: None
    """

    keyword = input("Input keyword to search: ").lower()
    tik = perf_counter()

    keyword_h = str(int.from_bytes(sha256(keyword.encode()).digest(),
                                   byteorder='big'))
    sql_query_1 = f'SELECT * FROM sse_keywords WHERE sse_keyword ={keyword_h}'

    connection = args[0]
    with connection.cursor() as cursor:
        cursor.execute(sql_query_1)
        result = cursor.fetchall()

        if len(result) == 0:
            print("No files containing the keyword found!")
            return
        else:

            """Calculates csp_keywords_address value"""
            values = result[0]
            num_files = values[2]
            num_search = values[3]
            str_1_conc = keyword_h + str(num_search)
            kw = str(int.from_bytes(sha256(str_1_conc.encode()).digest(),
                                    byteorder='big'))
            str_2_conc = kw + str(num_files)
            csp_keyword_addr = str(
                int.from_bytes(sha256(str_2_conc.encode()).digest(),
                               byteorder='big'))

            """Fetches all entries where the csp_keywords_address is present"""
            sql_query_2 = f'SELECT * FROM sse_csp_keywords WHERE csp_keywords_address ={csp_keyword_addr}'
            cursor.execute(sql_query_2)
            result = cursor.fetchall()

            if len(result) == 0:
                print("No files containing the keyword found!")
                return

            tok = time.perf_counter()

            """Recreate the cipher used while decrypting the database entries"""
            key = getpass("Input secret phrase that was used to encrypt the files: ")
            tik2 = time.perf_counter()
            key = sha256(key.encode()).digest()
            nonce = input("Enter nonce used while processing the files: ").encode()
            nonce = base64.b64decode(nonce)
            cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce)

            """Prints all filenames"""
            print(f'{len(result)} files containing keyword found;')
            for i in result:
                enc_str_bytes = base64.b64decode(i[2].encode("utf-8"))
                filename = cipher_dec.decrypt(enc_str_bytes).decode()
                print("   " + filename.split(".txt")[0] + ".txt")

            """Updates table sse_keywords"""
            new_numsearch = int(num_search) + 1
            sql_query_3 = f'UPDATE sse_keywords SET sse_keyword_numsearch={new_numsearch} WHERE sse_keyword ={keyword_h}'
            cursor.execute(sql_query_3)

            """Updates table sse_csp_keywords"""
            str_1_conc_new = keyword_h + str(new_numsearch)
            kw_new = str(
                int.from_bytes(sha256(str_1_conc_new.encode()).digest(),
                               byteorder='big'))
            str_2_conc_new = kw_new + str(num_files)
            csp_keyword_addr_new = str(
                int.from_bytes(sha256(str_2_conc_new.encode()).digest(),
                               byteorder='big'))
            sql_query_4 = f'UPDATE sse_csp_keywords SET csp_keywords_address={csp_keyword_addr_new} WHERE ' \
                          f'csp_keywords_address ={csp_keyword_addr}'
            cursor.execute(sql_query_4)

    tok2 = perf_counter()
    print(f'Keyword searching took {(tok-tik) + (tok2-tik2):3f} seconds\n')


def process_file(chunk, file, config, nonce, init_val, enc_key):
    """
    Processes one part of a file
    :param chunk: Part of one file
    :param file: Filename / or path to be precise
    :param config: MySQL connection object
    :param nonce: Nonce to use in creating cipher
    :param init_val: Counters value to use in creating cipher
    :param enc_key: Key to use in creating cipher
    :return:
    """

    with connect(**config) as cnx:
        cursor = cnx.cursor()

        """Create AES cipher object to use for one chunk, predetermined parameters"""
        cipher_enc = AES.new(enc_key, AES.MODE_CTR, initial_value=init_val, nonce=nonce)

        for word, value in chunk.items():

            w_hash = str(int.from_bytes(sha256(word.encode()).digest(),
                                        byteorder='big'))
            num_search = 0
            is_keyword = value[0]
            num_files = value[1]

            """Creates queries for filling table sse_keywords"""
            if is_keyword:
                sql_query_1 = f'INSERT INTO sse_keywords ' \
                              f'(sse_keyword, sse_keyword_numfiles, sse_keyword_numsearch) ' \
                              f'VALUES ({w_hash}, {num_files}, {num_search})'
                cursor.execute(sql_query_1)

            """Creates queries for filling table sse_csp_keywords"""
            str_1_conc = w_hash + str(num_search)
            kw = str(int.from_bytes(sha256(str_1_conc.encode()).digest(),
                                    byteorder='big'))
            str_2_conc = kw + str(num_files)
            csp_keyword_addr = str(
                int.from_bytes(sha256(str_2_conc.encode()).digest(),
                               byteorder='big'))
            str_3_conc = str(file) + str(num_files)
            csp_keyvalue = base64.b64encode(cipher_enc.encrypt(str_3_conc.encode())).decode("utf-8")

            sql_query_2 = f'INSERT INTO sse_csp_keywords (csp_keywords_address, csp_keyvalue) VALUES ' \
                          f'("{csp_keyword_addr}", "{csp_keyvalue}")'
            cursor.execute(sql_query_2)

        """Commits the modifications to the database"""
        cnx.commit()


def read_files(filenames):
    """
    Generates a dictionary from the file contents
    :param filenames: Files to process
    :return: Generator object to yield dictionary entries
    """

    """Dict keywords_sse contains all UNIQUE words OVERALL, structure; {str key : int num_files}"""
    keywords_sse = {}
    words_by_file = {}

    """File indexing ignores stop words such as "in, the, at, a, an" to limit the amount of keywords and (w,id)
     pairs. This same trick is also used by search engines"""
    stop_words = ["the", "in", "a", "an", "on", "at", "is", "of", "by", "it",
                  "that", "this", "he", "she", "him", "her",
                  "from", "by", "to", "as", "they", "them", "was", "were",
                  "yes", "no"]

    """Loops though all words in files, updates the two dicts previously mentioned"""
    for name in filenames:

        """Read contents of one file"""
        with open(name, 'r') as f:
            content = f.read().split()

            """Keeps count of the UNIQUE words in the current file, structure; {str word: (bool is_unique, int num)}"""
            file_words_u = {}
            for word in content:

                """Removes special characters from word and converts it to 
                lowercase and checks if the word is an ignorable stop word"""
                word = helper_funcs_ctr.strip_word(word)
                if word not in stop_words:

                    """Finds out if the current word is a known keyword"""
                    truth_flag = (word not in keywords_sse)
                    if truth_flag:
                        keywords_sse[word] = 1
                        file_words_u[word] = [truth_flag, 1]

                    else:
                        """Checks if the current word appears for the first time in file"""
                        if word not in file_words_u:
                            keywords_sse[word] += 1
                            file_words_u[word] = [truth_flag, 1]

        words_by_file[name] = file_words_u

    """Update each entrys num_files value and yield the values when called"""
    for file, file_c in words_by_file.items():

        for word in file_c.keys():
            file_c[word][1] = keywords_sse[word]

        yield file, file_c


def input_files(args):
    """
    Processes all .txt files in a given folder
    :param args: tuple containing MySQL connection object and config file to establish new MySQL connection
    :return: None
    """

    file_path = Path(
        input("Enter absolute path to the folder to use: ")).rglob('*.txt')
    tik = perf_counter()
    files = [x for x in file_path]
    length = len(files)

    if length == 0:
        print("No .txt files in the folder!")
        return

    """Generates a dictionary that holds word contents of each file"""
    words_by_file = read_files(files)

    """Now processes the words in the created dictionaries"""
    connection = args[0]
    config = args[1]

    """Empties the existing tables to make room for the new entries"""
    db_funcs.empty_tables(connection)

    """Ask for encryption key to use and creates AES cipher based on it"""
    enc_key = getpass("Input secret phrase to use as encryption/decryption key on this session: ")
    enc_key = sha256(enc_key.encode()).digest()
    nonce = Random.get_random_bytes(16)

    iterations = 0
    helper_funcs_ctr.print_progress_bar(iterations, length + 1,
                                    prefix='Processing files: ',
                                    suffix='Complete', length=50)

    """Loops through unique words by file, responsible for filling the tables in database"""
    for file, file_c in words_by_file:

        """Process one file at a time, 1 process per chunk. 
        Divides file contents based on the users CPU count"""
        chunk_length = int(len(file_c) / cpu_count() + 1)
        gen_chunks = helper_funcs_ctr.chunks(file_c, chunk_length)
        processes = []

        init_val = 0
        for chk in gen_chunks:

            """Start process for each chunk, calculate ciphers Counter value"""
            chk_size = sys.getsizeof(chk)
            chk_blocks = int((chk_size / 16) + 1)

            p = multiprocessing.Process(target=process_file,
                                        args=(chk, file, config, nonce, init_val, enc_key))

            processes.append(p)
            p.start()
            init_val += chk_blocks

        """Waits until all initiated processes are done"""
        for p in processes:
            p.join()

        iterations += 1
        helper_funcs_ctr.print_progress_bar(iterations, length + 1,
                                        prefix='Processing files: ',
                                        suffix='Complete', length=50)

    """Now encrypt the processed files, creates new cipher"""
    used_nonce = helper_funcs_ctr.encrypt_folder(files, enc_key)

    iterations += 1
    helper_funcs_ctr.print_progress_bar(iterations, length + 1,
                                    prefix='Processing files: ',
                                    suffix='Complete', length=50)

    print(f'\n{used_nonce}\n')
    print(f'Nonce used in encrypting the database was {base64.b64encode(nonce).decode("utf-8")}'
          f'\nStore it as it is REQUIRED when SEAECHING FOR KEYWORDS!\n')

    tok2 = perf_counter()
    print(f'File processing took {(tok2 - tik) / 60:3f} minutes')
    print(
        f'Unique keywords: {db_funcs.table_size("sse_keywords", connection)}')
    print(
        f'(w,id) pairs: {db_funcs.table_size("sse_csp_keywords", connection)}')


def main():
    """Connects to a previously created, preferably empty, MySQL database"""

    try:
        """Config for establishing connection to the database"""
        config = {'user': str(input("Enter MySQL username: ")),
                  'password': getpass("Enter MySQL password: "),
                  'host': 'localhost',
                  'database': str(input("Select DB to connect to: ")),
                  'buffered': True}

        with connect(**config) as cnx:
            print(f'Connected to {config["database"]}!')

            """Dictionary to store function calls"""
            func_dict = {"S": (search, (cnx,)),
                         "CT": (db_funcs.create_tables, (cnx,)),
                         "DT": (db_funcs.drop_tables, (cnx,)),
                         "IF": (input_files, (cnx, config)),
                         "DFILE": (helper_funcs_ctr.decrypt_file, ""),
                         "DFOLDER": (helper_funcs_ctr.decrypt_folder, ""),
                         "D": (delete, (cnx,)),
                         "M": (modify, (cnx,))}

            """Main interface of the program"""
            running = True
            while running:
                choice = input(
                    "Enter command, type <H> for help and <Q> to quit: ").upper()

                if choice == "Q":
                    print("Goodbye!")
                    running = False

                elif choice == "H":
                    print("S = SEARCH\n"
                          "IF = INPUT FILES\n"
                          "M = MODIFY FILE\n"
                          "D = DELETE FILE\n"
                          "CT = CREATE TABLES\n"
                          "DT = DROP TABLES\n"
                          "DFILE = DECRYPTS A FILE\n"
                          "DFOLDER = DECRYPTS FILES IN FOLDER\n")

                elif choice in func_dict.keys():
                    func_dict[choice][0](func_dict[choice][1])

                else:
                    print("Invalid input!")

    except Error as e:
        print(e)


if __name__ == '__main__':
    """Forces multiprocessing to start processes with 'spawn', default in Mac and Windows.
    On Linux 'fork' is default. Windows doesn't have 'fork'. 'spawn' is also
    more reliable/safe across the board. Performance wise, 'fork' is faster 
    than 'spawn' """
    multiprocessing.set_start_method('spawn')
    main()
