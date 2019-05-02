from flask import  render_template, url_for,flash, redirect,request,send_from_directory
from flaskblog.forms import RegistrationForm, LoginForm,QuestionForm
from flask_login import login_user, current_user, logout_user, login_required

from flaskblog.models import User,Message
from flaskblog import app,db,bcrypt
from keras.models import load_model
import os 
import tensorflow as tf
import numpy as np
from PIL import Image as image
import keras.backend as k
from sklearn.utils import shuffle
import operator
from werkzeug import secure_filename

global model,graph
UPLOAD_FOLDER = 'C:/Users/Anjali/Desktop/django/flasksite/flaskblog/static/images'

def allowed_file(filename):
    ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg','PNG','gif'])
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/que",methods=['GET','POST'])
def que():
    form = QuestionForm() 
    if form.validate_on_submit():
        email = User.query.filter_by(email=form.email.data).first()
        user=User.query.filter_by(username=form.username.data).first()
        if email and user :
            que = Message(username=form.username.data, email=form.email.data,message=form.message.data)
            db.session.add(user)
            db.session.commit()
            flash("Your message has been received!!","success")
            return redirect((url_for('home'))) 
    return render_template('que.html',form=form)

@app.route("/select_image",methods=['GET','POST'])
def select_image():

    def predict_with_uncertainty(f, x, no_classes, n_iter=100):
        result = np.zeros((n_iter,) + (x.shape[0], no_classes) )
        for i in range(n_iter):
            result[i,:, :] = f((x, 1))[0]
        prediction = result.mean(axis=0)
        uncertainty = result.std(axis=0)
        return prediction, uncertainty 

    def pred(filename):
        with k.get_session().graph.as_default():
            new=load_model("C:/Users/Anjali/Desktop/django/mysite/pages/saved.h5")
            new.compile(optimizer='adam',loss='categorical_crossentropy',metrics=['accuracy'])
            path="C:/Users/Anjali/Desktop/django/flasksite/flaskblog/static/images/"
            im=image.open(path+filename,"r")    
            j=im.resize((28,28))
            gray_li=im.convert(mode='L')
            grayim=gray_li.resize((28,28))
            #grayim.save("gray-bbs-1","png")
            img=np.array([np.array(grayim) ],'f')   
            a=img.reshape(1,28,28,1)
            f=k.function([new.layers[0].input,k.learning_phase()],[new.layers[-1].output])
            x,z=predict_with_uncertainty(f,a,3)
            for i in x:
                a1=i
            index, value = max(enumerate(a1), key=operator.itemgetter(1))
            z1=z[0]  
            for i in range(len(z1)):
                if(index==i):
                    un=z1[i]  
            if(value>0.5 and un<0.48):
                if(index==0):
                    return "The predicted disease is sigatoka"
                elif(index==1):
                    return "The predicted disease is black wilt"
                if(index==2):
                    return "It's a healthy leaf"  
            else:
                return "Sorry unable to predict"
       


    if request.method == 'POST':
        # check if the post request has the file part
            if 'file1' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file1']
        # if user does not select file, browser also
        # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                #file_path='C:/Users/Anjali/Desktop/django/flasksite/flaskblog/static/images/'+filename
                prediction=pred(filename)
                return render_template('select_image.html',pred=prediction,filename=filename)
    return render_template('select_image.html')

@app.route('/C:/Users/Anjali/Desktop/django/flasksite/flaskblog/static/images/<filename>')
def send_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/registration", methods=['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('registration.html',form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html',form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account")
@login_required
def account():
    return render_template('account.html')
