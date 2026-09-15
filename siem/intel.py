import ipaddress, json, re
from siem import store
KINDS={'ip','domain','url','hash','vulnerability'}
def validate(kind,value):
    value=value.strip()
    if kind not in KINDS or not value: raise ValueError('不支援的情資類型或空值')
    if kind=='ip':
        try: ipaddress.ip_address(value)
        except ValueError: raise ValueError('IP 格式不正確')
    if kind=='domain' and not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',value): raise ValueError('網域格式不正確')
    if kind=='hash' and not re.fullmatch(r'[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}',value): raise ValueError('Hash 格式不正確')
    return value
def list_items(q='',kind='',verdict='',page=1,size=50,sort='last_seen'):
    clauses=['1=1']; params=[]
    if q: clauses.append('(value LIKE ? OR source LIKE ? OR notes LIKE ?)'); params += [f'%{q}%']*3
    if kind: clauses.append('kind=?'); params.append(kind)
    if verdict: clauses.append('verdict=?'); params.append(verdict)
    where=' AND '.join(clauses)
    with store.connection() as db:
        total=db.execute('SELECT count(*) FROM intelligence WHERE '+where,params).fetchone()[0]
        order={'last_seen':'last_seen DESC','confidence':'confidence DESC,last_seen DESC','value':'value ASC'}.get(sort,'last_seen DESC')
        rows=db.execute('SELECT * FROM intelligence WHERE '+where+' ORDER BY '+order+' LIMIT ? OFFSET ?',params+[size,(page-1)*size]).fetchall()
        return {'total':total,'items':[dict(r) for r in rows]}
def upsert(kind,value,source='manual',confidence=0,verdict='unknown',tags=None,notes='',actor='dashboard'):
    value=validate(kind,value); ts=store.now(); tags=json.dumps(tags or [],ensure_ascii=False)
    with store.connection() as db:
        row=db.execute('SELECT id FROM intelligence WHERE kind=? AND value=? AND source=?',(kind,value,source)).fetchone()
        if row:
            db.execute('UPDATE intelligence SET confidence=?,verdict=?,tags=?,last_seen=?,notes=? WHERE id=?',(confidence,verdict,tags,ts,notes,row[0])); item_id=row[0]
        else:
            item_id=db.execute('INSERT INTO intelligence(kind,value,source,confidence,verdict,tags,first_seen,last_seen,notes) VALUES (?,?,?,?,?,?,?,?,?)',(kind,value,source,confidence,verdict,tags,ts,ts,notes)).lastrowid
        store.audit('intel.upsert',f'{kind}:{value} ({source})',actor=actor,db=db)
        return dict(db.execute('SELECT * FROM intelligence WHERE id=?',(item_id,)).fetchone())
def remove(item_id,actor='dashboard'):
    with store.connection() as db:
        if not db.execute('DELETE FROM intelligence WHERE id=?',(item_id,)).rowcount: raise ValueError('找不到情資')
        store.audit('intel.delete',f'#{item_id}',actor=actor,db=db)
