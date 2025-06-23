import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from crypto_core import encrypt_data, decrypt_data
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'very_secret_key'

USERNAME = 'كتائب القسام'
with open('password.txt', 'r', encoding='utf-8') as f:
    stored_password = f.read().strip()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == USERNAME and request.form['password'] == stored_password:
            session['logged_in'] = True
            return redirect('/home')
        else:
            flash('بيانات الدخول غير صحيحة')
    return render_template('login.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    global stored_password
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    result = None
    file_url = None

    if request.method == 'POST':
        action = request.form['action']

        if action == 'change_password':
            old = request.form.get('old_password')
            new = request.form.get('new_password')
            if old == stored_password and new:
                stored_password = new
                with open('password.txt', 'w', encoding='utf-8') as f:
                    f.write(new)
                result = "✅ تم تغيير كلمة المرور بنجاح"
            else:
                result = "❌ كلمة المرور الحالية غير صحيحة"

        else:
            password = request.form.get('password')
            file = request.files.get('file')
            if file and password:
                file_bytes = file.read()
                try:
                    if action.startswith('encrypt'):
                        processed = encrypt_data(file_bytes, password)
                        filename = secure_filename(file.filename) + '.enc'
                    elif action == 'decrypt':
                        processed = decrypt_data(file_bytes, password)
                        filename = secure_filename(file.filename).replace('.enc', '')
                    else:
                        result = "❌ إجراء غير معروف"
                        return render_template('home.html', result=result)

                    if action == 'encrypt_direct':
                        return send_file(
                            BytesIO(processed),
                            download_name=filename,
                            as_attachment=True
                        )
                    else:
                        save_path = os.path.join('static', 'files')
                        os.makedirs(save_path, exist_ok=True)
                        full_path = os.path.join(save_path, filename)
                        with open(full_path, 'wb') as f:
                            f.write(processed)
                        file_url = '/' + full_path.replace('\\', '/').replace(os.path.sep, '/')
                        result = f"✅ تم إنشاء الملف: {filename}"

                except Exception as e:
                    result = f"❌ خطأ: {str(e)}"
            else:
                result = "❌ يرجى رفع ملف وإدخال كلمة المرور"

    return render_template('home.html', result=result, file_url=file_url)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)



