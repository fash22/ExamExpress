from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, request, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import Form
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from wtforms import StringField, PasswordField, SelectField, SubmitField, validators, RadioField
from wtforms.fields.html5 import DateField


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/database.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = 'secret gani'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class Examinee(db.Model, UserMixin):
    __tablename__ = 'examinees'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(20), nullable=False)
    middle_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    first_priority = db.Column(db.String(10), nullable=False)
    second_priority = db.Column(db.String(10), nullable=False)
    third_priority = db.Column(db.String(10), nullable=False)
    school = db.Column(db.String(100), nullable=False)
    graduated = db.Column(db.Date(), nullable=False)

    score_eng = db.Column(db.Integer)
    score_fil = db.Column(db.Integer)
    score_gen = db.Column(db.Integer)
    score_mat = db.Column(db.Integer)
    score_sci = db.Column(db.Integer)
    score_total = db.Column(db.Integer)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Examinee>: %s %s' % (self.first_name, self.last_name)

class ExamQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_number = db.Column(db.Integer)
    subject = db.Column(db.String(20))
    question = db.Column(db.String(150))
    choice_A = db.Column(db.String(20))
    choice_B = db.Column(db.String(20))
    choice_C = db.Column(db.String(20))
    choice_D = db.Column(db.String(20))
    answer = db.Column(db.String(2))

    def __repr__(self):
        return '<Question>: %s => %s' % (self.subject, self.question)


class LoginForm(Form):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Submit')

class RegistrationForm(LoginForm):
    verify_password = PasswordField('Verify Password', validators=[validators.Required()])
    first_name = StringField('First Name', validators=[validators.InputRequired()])
    middle_name = StringField('Middle Name', validators=[validators.InputRequired()])
    last_name = StringField('Last Name', validators=[validators.InputRequired()])
    school = StringField('Name of School', validators=[validators.InputRequired()])
    date_graduated = DateField('Date of Graduation')

    ch = [('bsba','BSBA'), ('bsentrep', 'BSEntrep'), ('bsoa','BSOA'), ('bsisact','BSIS/ACT'), ('bsit','BSIT'), ('beed','BEED'), ('bsed','BSED')]
    first_priority = SelectField('First Priority', choices=ch, validators=[validators.InputRequired(),])
    second_priority = SelectField('Second Priority', choices=ch, validators=[validators.InputRequired()])
    third_priority = SelectField('Third Priority', choices=ch, validators=[validators.InputRequired()])

class QustionForm(Form):
    def __init__(self, question, c_a, c_b, c_c, c_d):
        self.question = RadioField(question, choices=[c_a,c_b,c_c,c_d], validators=[validators.InputRequired()])

@login_manager.user_loader
def load_user(user_id):
    return Examinee.query.get(user_id)

@login_manager.unauthorized_handler
def unauthorized():
    # do stuff
    return make_response(render_template('unauthorized.html', user=current_user), 401)

@app.errorhandler(404)
def not_found(error):
    resp = make_response(render_template('error404.html', user=current_user), 404)
    return resp


@app.route('/')
def home():
    return render_template('welcome.html', user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        try:
            u = Examinee.query.filter_by(username=form.username.data).all()[0]
            if u.verify_password(form.password.data):
                login_user(u)
                return render_template('account_review.html', examinee=current_user)
            else:
                return render_template('login.html', error="Incorrect Password", form=form)
        except IndexError as err:
            return render_template('login.html', error='Account Not found', form=form)

    return render_template('login.html', form=form, user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        user = Examinee()
        user.username = form.username.data
        user.password = form.password.data
        user.first_name = form.first_name.data
        user.middle_name = form.middle_name.data
        user.last_name = form.last_name.data
        user.school = form.school.data
        user.graduated = form.date_graduated.data
        user.first_priority = form.first_priority.data
        user.second_priority = form.second_priority.data
        user.third_priority = form.third_priority.data

        db.session.add(user)
        db.session.commit()

        login_user(user)
        return render_template('account_review.html', examinee=current_user)

    return render_template('register.html', form=form, user=current_user)


@app.route('/exam/general-instructions')
@login_required
def general_instructions():
    return render_template('general_instructions.html', user=current_user)

@app.route('/exam')
@login_required
def exam():
    q_eng = ExamQuestion.query.filter_by(subject='ENG').all()
    q_fil = ExamQuestion.query.filter_by(subject='FIL').all()
    q_gen = ExamQuestion.query.filter_by(subject='GEN').all()
    q_mat = ExamQuestion.query.filter_by(subject='MAT').all()
    q_sci = ExamQuestion.query.filter_by(subject='SCI').all()
    exam = {'eng':q_eng, 'fil':q_fil, 'gen':q_gen, 'mat':q_mat, 'sci':q_sci}

    return render_template('exams.html', exam=exam, user=current_user)


@app.route('/exam/check', methods=['POST','GET'])
@login_required
def exam_check():
    total_points = 0
    eng_points = 0
    fil_points = 0
    gen_points = 0
    mat_points = 0
    sci_points = 0

    # retrieve POST request data and convert it to list
    answer_data = request.get_data(as_text=True).split('&')
    answers = list()

    # convert the answer_data list into a list of dictionary for convenience
    for answer in answer_data:
        item, val = answer.split('=')
        answers.append({'item_number': item, 'ans': val})

    # compare all the individual answer of the user to the correct answer stored in the database
    for item in answers:
        exam_question = ExamQuestion.query.filter(ExamQuestion.item_number == item['item_number']).all()[0]
        if item['ans'] == exam_question.answer:
            total_points = total_points + 1
            if exam_question.item_number[0] == 'E':
                eng_points = eng_points + 1
            if exam_question.item_number[0] == 'F':
                fil_points = fil_points + 1
            if exam_question.item_number[0] == 'G':
                gen_points = gen_points + 1
            if exam_question.item_number[0] == 'M':
                mat_points = mat_points + 1
            if exam_question.item_number[0] == 'S':
                sci_points = sci_points + 1
    points = {
        'eng_points': eng_points,
        'fil_points': fil_points,
        'gen_points': gen_points,
        'mat_points': mat_points,
        'sci_points': sci_points,
        'total_points': total_points,
    }

    current_user.score_eng = points['eng_points']
    current_user.score_fil = points['fil_points']
    current_user.score_gen = points['gen_points']
    current_user.score_mat = points['mat_points']
    current_user.score_sci = points['sci_points']
    current_user.score_total = points['total_points']

    print(current_user)
    db.session.commit()


    return render_template('exam_result.html', points=points, user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('logout.html', user=current_user)

if __name__ == '__main__':
    app.run()
