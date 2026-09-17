"""Export portable credentials without copying logs or the SIEM database."""
import argparse
import os
import sys
from pathlib import Path
from dotenv import dotenv_values

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
KEYS=('SIEM_ADMIN_USERNAME','SIEM_ADMIN_PASSWORD','OPENAI_API_KEY','ABUSEIPDB_API_KEY',
      'LINE_CHANNEL_ACCESS_TOKEN','LINE_CHANNEL_SECRET','LINE_USER_IDS','NGROK_AUTHTOKEN')

def quote(value):
    value=str(value or '')
    if not value or all(c.isalnum() or c in '._-,:/@' for c in value): return value
    return '"'+value.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n')+'"'

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',default='secrets.env')
    args=parser.parse_args()
    source={**dotenv_values(ROOT/'.env'),**os.environ}
    values={key:source.get(key,'') for key in KEYS}
    values['SIEM_ADMIN_USERNAME']=values['SIEM_ADMIN_USERNAME'] or 'admin'
    values['SIEM_ADMIN_PASSWORD']=values['SIEM_ADMIN_PASSWORD'] or 'admin@ncu-siem'
    try:
        from siem import store
        store.init_db()
        with store.connection() as db:
            row=db.execute('SELECT provider,model,api_key FROM ai_settings WHERE id=1').fetchone()
        if row:
            values.update(AI_PROVIDER=row['provider'],AI_MODEL=row['model'],AI_API_KEY=row['api_key'])
    except Exception:
        pass
    values.setdefault('AI_PROVIDER','gemini')
    values.setdefault('AI_MODEL','gemini-3.5-flash-lite')
    values.setdefault('AI_API_KEY','')
    values['ENABLE_LINE']='true' if all(values.get(k) for k in ('LINE_CHANNEL_ACCESS_TOKEN','LINE_CHANNEL_SECRET','LINE_USER_IDS')) else 'false'
    values['ENABLE_NGROK']='true' if values['ENABLE_LINE']=='true' and bool(values.get('NGROK_AUTHTOKEN')) else 'false'
    output=(ROOT/args.output).resolve()
    output.write_text('\n'.join(f'{key}={quote(value)}' for key,value in values.items())+'\n',encoding='utf-8')
    try: os.chmod(output,0o600)
    except OSError: pass
    print(f'Exported {len(values)} settings to {output.name}; contents were not printed.')

if __name__=='__main__': main()
