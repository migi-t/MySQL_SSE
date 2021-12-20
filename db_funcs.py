"""File for all Database related functions"""


def table_size(table, connection):
    """
    Counts all the rows of the table
    :param table: Name of the table of which size user wants to know
    :param connection: MySQL connection object
    :return: Int(number of rows)
    """
    sql_query = f'SELECT COUNT(*) FROM {table};'
    with connection.cursor() as cursor:
        cursor.execute(sql_query)
        sql_response = cursor.fetchall()

    return sql_response[0][0]


def drop_tables(args):
    """
    Drops the used tables, used when user wants to modify table schemas etc
    :param args: MySQL connection object
    :return: None
    """

    sql_query_1 = "DROP TABLE sse_csp_keywords"
    sql_query_2 = "DROP TABLE sse_keywords"
    connection = args[0]
    with connection.cursor() as cursor:
        cursor.execute(sql_query_1)
        cursor.execute(sql_query_2)


def empty_tables(connection):
    """
    Empties tables sse_keywords and sse_csp_keywords
    :param connection: MySQL connection object
    :return: None
    """
    with connection.cursor() as cursor:

        """Empties existing tables"""
        sql_query_1 = "TRUNCATE TABLE sse_keywords"
        sql_query_2 = "TRUNCATE TABLE sse_csp_keywords"
        cursor.execute(sql_query_1)
        cursor.execute(sql_query_2)


def create_tables(args):
    """
    Creates two MySQL tables to the connected database
    :param args: MySQL connection object
    :return: None
    """

    sql_query_1 = """
    CREATE TABLE sse_csp_keywords (
        csp_keywords_id INT AUTO_INCREMENT PRIMARY KEY,
        csp_keywords_address VARCHAR(500),
        csp_keyvalue VARCHAR(1000)
    )
    """

    sql_query_2 = """
    CREATE TABLE sse_keywords (
        sse_keywords_id INT AUTO_INCREMENT PRIMARY KEY,
        sse_keyword VARCHAR(500),
        sse_keyword_numfiles VARCHAR(500),
        sse_keyword_numsearch VARCHAR(500)
    )
    """
    connection = args[0]
    with connection.cursor() as cursor:
        cursor.execute(sql_query_1)
        cursor.execute(sql_query_2)
