# -*- coding: utf-8 -*-
import json
from functools import wraps

import arrow
from flask import g, request, make_response, jsonify, abort

from application import db, app, limiter, cache, logger, access_logger
from models import Users, Scope
import helper
import helper_soap
from helper_cgs import QGCgs


@app.route('/')
@limiter.limit("5000/hour")
def index_get():
    result = {
        'hbc_url': 'http://%shbc{/hphm}{/hpzl}' % (request.url_root),
        'hbc_all_url': 'http://%shbc_all/' % (request.url_root)
    }
    header = {'Cache-Control': 'public, max-age=60, s-maxage=60'}
    return jsonify(result), 200, header


@cache.memoize(3600) #缓存
def get_hbcall_local(date):
    #sql = ("SELECT hphm, hpzl, ccdjrq FROM hzhbc.hbc_jgj_data where zt='1'")
    sql = ("SELECT hphm, hpzl, ccdjrq FROM hbt_huangbiaoche WHERE updatetime=to_date('{0}', 'yyyy-mm-dd hh24:mi:ss')".format(date))
    query = db.get_engine(app, bind='hbc').execute(sql)
    r = query.fetchall()
    query.close()
    return r


@app.route('/hbc_all/<string:date>', methods=['GET'])
@limiter.limit('5000/hour')
def hbcall_get(date):
    r = get_hbcall_local(date)
    items = []
    for i in r:
        hpzl = i[1].strip()
        if len(hpzl) == 1:
            hpzl = '0{0}'.format(hpzl)
        items.append({'hphm': i[0].decode('utf8'), 'hpzl': hpzl.decode('utf8'),
                      'ccdjrq': str(i[2])})
    return jsonify({'total_count': len(items), 'items': items}), 200


@cache.memoize(3600) #缓存
def get_hbc_local(hphm, hpzl):
    #sql = ("SELECT hphm, hpzl, ccdjrq FROM hzhbc.hbc_jgj_data where hphm='{0}' and hpzl='{1}' and zt='1'".format(hphm, hpzl))
    sql = ("SELECT hphm, hpzl, ccdjrq FROM hbt_huangbiaoche where hphm='{0}' AND hpzl='{1}'".format(hphm, hpzl))
    query = db.get_engine(app, bind='hbc').execute(sql)
    r = query.fetchone()
    query.close()
    return r


@app.route('/hbc_all/<string:hphm>/<string:hpzl>', methods=['GET'])
@limiter.limit('5000/hour')
def hbcall2_get(hphm, hpzl):
    r = get_hbc_local(hphm, hpzl)
    if r is not None:
        hpzl = r[1].strip()
        return jsonify({'hphm': r[0].decode('utf8'),
                        'hpzl': hpzl.decode('utf8'),
                        'ccdjrq': str(r[2])}), 200
    else:
        abort(404)


@app.route('/hbc/<string:hphm>/<string:hpzl>', methods=['GET'])
@limiter.limit('5000/hour')
def hbc_get(hphm, hpzl):
    try:
        ini = {
            'host': '127.0.0.1',
            'port': 8086
        }
        c = QGCgs(**ini)
        r = c.get_vehicle(hphm, hpzl)
    except Exception as e:
	logger.error(e)
    if r:
        return jsonify(r['info']), 200
    else:
        abort(404)


@app.route('/vehicle/<string:hphm>/<string:hpzl>', methods=['GET'])
@limiter.limit('5000/hour')
def vehicle_get(hphm, hpzl):
    try:
        ini = {
	    'host': '127.0.0.1',
	    'port': 8086
        }
        c = QGCgs(**ini)
        r = c.get_vehicle(hphm, hpzl)
	lm = arrow.get(r['last_modified']).replace(hours=-8).to('local')
	if arrow.now() > lm.replace(hours=24):
	    r = c.get_vehicle(hphm, hpzl, flush=True)
    except Exception as e:
	logger.error(e)
    if r:
        return jsonify(r['info']), 200
    else:
        abort(404)
