from app import db, Examinee ,ExamQuestion

examinees = Examinee.query.all()
questions = ExamQuestion.query.all()

def list_all(l):
    for i in l:
        print('%d: %s' % (i.id, i))

list_all(examinees)
list_all(questions)