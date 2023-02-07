import os
import psycopg2

# ЭТОТ ФАЙЛ НУЖЕН ДЛЯ СОЗДАНИЯ БД
# 1. Создай БД, юзера и назначь ему пароль в psql, дай доступ юзеру к бд
# 2. Создай файл init_db.py в нем создаются таблицы БД
# 3. Выполнить init_db.py для добавления контента в БД
# 4. Подключись к БД в psql
# 5. \c flask_db 

conn = psycopg2.connect(
        host="localhost",
        database="flask_db",
        user=os.environ['DB_USERNAME'],
        password=os.environ['DB_PASSWORD']
        )

# Open a cursor to perform database operations
cur = conn.cursor()

# Execute a command: this creates a new table
cur.execute('DROP TABLE IF EXISTS books;')
cur.execute('CREATE TABLE books (id serial PRIMARY KEY,'
                                 'title varchar (150) NOT NULL,'
                                 'author varchar (50) NOT NULL,'
                                 'pages_num integer NOT NULL,'
                                 'review text,'
                                 'date_added date DEFAULT CURRENT_TIMESTAMP);'
                                 )

# Insert data into the table

cur.execute('INSERT INTO books (title, author, pages_num, review)'
            'VALUES (%s, %s, %s, %s)',
            ('Dmitry Rusanow',
             'big dick',
             13,
             'A great cock!')
            )


cur.execute('INSERT INTO books (title, author, pages_num, review)'
            'VALUES (%s, %s, %s, %s)',
            ('Ilya Piskunov',
             'lil dick',
             9,
             'Another great cock!')
            )

conn.commit()

cur.close()
conn.close()

