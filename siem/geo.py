"""Best-effort public IP geolocation with a persistent local cache."""
import ipaddress
import time
import requests
from siem import store

URL='https://ipinfo.io/{ip}/json'

# RFC 5737 documentation networks are safe synthetic attackers. Assign them
# stable worldwide locations so a competition demo can exercise the map
# without accusing the real owner of a public IP address.
DEMO_NETWORKS=(ipaddress.ip_network('192.0.2.0/24'),ipaddress.ip_network('198.51.100.0/24'),ipaddress.ip_network('203.0.113.0/24'))
DEMO_LOCATIONS=(
    ('US','United States','San Francisco','California',37.7749,-122.4194),
    ('DE','Germany','Frankfurt','Hesse',50.1109,8.6821),
    ('JP','Japan','Tokyo','Tokyo',35.6762,139.6503),
    ('SG','Singapore','Singapore','Singapore',1.3521,103.8198),
    ('AU','Australia','Sydney','New South Wales',-33.8688,151.2093),
    ('BR','Brazil','São Paulo','São Paulo',-23.5505,-46.6333),
    ('NL','Netherlands','Amsterdam','North Holland',52.3676,4.9041),
    ('ZA','South Africa','Johannesburg','Gauteng',-26.2041,28.0473),
)

def demo_location(address):
    if not any(address in network for network in DEMO_NETWORKS): return None
    code,country,city,region,lat,lon=DEMO_LOCATIONS[int(address)%len(DEMO_LOCATIONS)]
    return {'status':'demo','country':country,'country_code':code,'city':city,'region':region,
            'latitude':lat,'longitude':lon,'org':'NCU-PDCLAB simulated external source'}

def enrich(ip):
    try:
        address=ipaddress.ip_address(ip)
    except ValueError:
        return {'status':'invalid'}
    simulated=demo_location(address)
    if simulated: return simulated
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

def refresh_demo_locations():
    """Replace older LAN cache entries after enabling synthetic world locations."""
    with store.connection() as db:
        ips=[row['ip'] for row in db.execute('SELECT ip FROM geo_ip_cache')]
    for ip in ips:
        try: data=demo_location(ipaddress.ip_address(ip))
        except ValueError: data=None
        if data: save(ip,data)

def main():
    store.init_db()
    refresh_demo_locations()
    while True:
        with store.connection() as db:
            row=db.execute('SELECT DISTINCT e.src_ip FROM events e LEFT JOIN geo_ip_cache g ON g.ip=e.src_ip WHERE g.ip IS NULL ORDER BY e.timestamp DESC LIMIT 1').fetchone()
        if row: save(row['src_ip'],enrich(row['src_ip']))
        time.sleep(2 if row else 10)

if __name__=='__main__': main()
