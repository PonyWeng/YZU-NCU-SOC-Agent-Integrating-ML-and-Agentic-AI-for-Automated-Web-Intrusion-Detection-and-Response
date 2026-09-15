"""Best-effort public IP geolocation with a persistent local cache."""
import ipaddress
import time
import requests
from siem import store

URL='https://ipinfo.io/{ip}/json'

def enrich(ip):
    try:
        address=ipaddress.ip_address(ip)
    except ValueError:
        return {'status':'invalid'}
    if not address.is_global:
        return {'status':'internal','country':'Internal','country_code':'LAN'}
    try:
        response=requests.get(URL.format(ip=ip),timeout=8)
        response.raise_for_status(); data=response.json()
        lat,lon=(data.get('loc','').split(',')+['',''])[:2]
        return {'status':'ok','country':data.get('country','無法定位'),'country_code':data.get('country','N/A'),
                'city':data.get('city',''),'region':data.get('region',''),
                'latitude':float(lat) if lat else None,'longitude':float(lon) if lon else None,
                'org':data.get('org','')}
    except Exception:
        return {'status':'unavailable','country':'無法定位','country_code':'N/A'}

def save(ip,data):
    fields=('country','country_code','city','region','latitude','longitude','org','status')
    values=[data.get(k) for k in fields]
    with store.connection() as db:
        db.execute('INSERT OR REPLACE INTO geo_ip_cache(ip,country,country_code,city,region,latitude,longitude,org,status,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
                   [ip,*values,store.now()])

def main():
    store.init_db()
    while True:
        with store.connection() as db:
            row=db.execute('SELECT DISTINCT e.src_ip FROM events e LEFT JOIN geo_ip_cache g ON g.ip=e.src_ip WHERE g.ip IS NULL ORDER BY e.timestamp DESC LIMIT 1').fetchone()
        if row: save(row['src_ip'],enrich(row['src_ip']))
        time.sleep(2 if row else 10)

if __name__=='__main__': main()
