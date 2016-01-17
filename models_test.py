# -*- coding: utf-8 -*-
import json

import arrow

from application import db
from application.models import Users, Scope

def user_get():
    user = Users.query.first()
    print user.username == 'admin'

def scope_get():
    s = Scope.query.first()
    print s.name == 'all'


if __name__ == '__main__':
    user_get()
    scope_get()
