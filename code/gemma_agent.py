"""Optional local Gemma policy interpretation (Ollama HTTP API).

Requires Ollama running locally and an installed Gemma model. The LLM response
is strictly reviewed using policy_agent.validate_advice. It never changes audit status.
"""
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from policy_agent import build_policy_request,validate_advice

LOG = Path(__file__).resolve().parents[1]/'ghosttrace_model_usage.jsonl'

def interpret(rule,facts,model='gemma3:4b',host=None):
    if not isinstance(facts,dict):raise ValueError('facts must be a dict')
    # Explicit permitlist: only booleans and short enums are allowed; do not send raw user PII.
    if any(not isinstance(v,(bool,int,float)) and not (isinstance(v,str) and v in {'YES','NO','UNKNOWN','ACTIVE','INACTIVE'}) for v in facts.values()):
        raise ValueError('Use non-sensitive boolean/enum facts only')
    prompts=build_policy_request(rule,facts)
    url=(host or os.environ.get('OLLAMA_HOST','http://127.0.0.1:11434')).rstrip('/')+'/api/chat'
    body={'model':model,'stream':False,'format':'json', 'messages':[
       {'role':'system','content':prompts['system']}, {'role':'user','content':prompts['user']}],
       'options':{'temperature':0}}
    req=urllib.request.Request(url,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=120) as response:
        result=json.loads(response.read().decode())
    reply=result['message']['content']
    advice=validate_advice(reply,rule,facts)
    usage={'timestamp':datetime.now(timezone.utc).isoformat(),'provider':'ollama_local','model':model,
           'prompt_eval_count':result.get('prompt_eval_count'),'eval_count':result.get('eval_count'),
           'rule_id':rule['rule_id'], 'cost_usd':'local model; no provider API charge; compute costs not measured'}
    with LOG.open('a',encoding='utf-8') as f:f.write(json.dumps(usage)+'\n')
    return {'validated_policy_advice':advice,'usage':usage,
            'warning':'Advisory only. Does not modify deletion findings or output.csv.'}
