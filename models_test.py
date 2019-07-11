# -*- coding: utf-8 -*-
import json

import arrow

from application import app, db
from application.models import Users, Scope

def user_get():
    user = Users.query.first()
    print user.username == 'admin'

def scope_get():
    s = Scope.query.first()
    print s.name == 'all'

def hbcall_get():
    sql = ("SELECT A.FZJG, A.HPHM, A.HPZL, A.CCDJRQ FROM HBC_ALL_VIEW A")
    query = db.engine.execute(sql)
    r = query.fetchall()
    query.close()
    print r[0]

def sms_get():
    #print db.get_engine(app, bind='sms')
    sql = ("select * from sms limit 10")
    query = db.get_engine(app, bind='sms').execute(sql)
    r = query.fetchall()
    query.close()
    print r[0]


if __name__ == '__main__':
    #user_get()
    #scope_get()
    #hbcall_get()
    sms_get()
