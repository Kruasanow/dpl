############ DATABASE ###############

 1. Создай БД, юзера и назначь ему пароль в psql, дай доступ юзеру к бд
 2. Создай файл init_db.py в нем создаются таблицы БД
 3. Добавить переменные окружения для пароля и пользователя через export 
 4. Выполнить init_db.py для добавления контента в БД
 5. Подключись к БД в psql
 6. \c flask_db

example:
        @app.route('/create/', methods=('GET', 'POST'))
        def create():
            if request.method == 'POST':
                title = request.form['title']
                author = request.form['author']
                pages_num = int(request.form['pages_num'])
                review = request.form['review']

                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute('INSERT INTO books (title, author, pages_num, review)'
                            'VALUES (%s, %s, %s, %s)',
                            (title, author, pages_num, review))
                conn.commit()
                cur.close()
                conn.close()
                return redirect(url_for('index'))

            return render_template('create.html'