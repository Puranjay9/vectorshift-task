# slack.py

from fastapi import Request , HTTPException
from fastapi.responses import HTMLResponse
import secrets 
import json
import httpx
import asyncio
import base64
import requests
from integrations.integration_item import IntegrationItem


from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

CLIENT_ID = '91d974d0-cd22-4de4-92aa-a1cc8328e3ef'
CLIENT_SECRET = '2c1053d9-0b09-48d5-9bb6-36b4b21a85c7'
encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()

REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
authorization_url = 'https://app-na2.hubspot.com/oauth/authorize?client_id=91d974d0-cd22-4de4-92aa-a1cc8328e3ef&redirect_uri=http://localhost:8000/integrations/hubspot/oauth2callback&scope=oauth'


async def authorize_hubspot(user_id, org_id):
    # TODO
    state_data = {
        'state' : secrets.token_urlsafe(32),
        'user_id' : user_id,
        'org_id' : org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}',encoded_state,expire=600)

    return f'{authorization_url}&state={encoded_state}'


async def oauth2callback_hubspot(request: Request):
    # TODO
    if request._query_params.get('error'):
        raise HTTPException(status_code=400 , detail=request.query_params.get('error'))
    
    code = request.query_params.get('code')
    print("code" , code)
    state_param = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(state_param.encode()).decode())
    print("state_data" , state_data)

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    print("state data" , original_state , user_id , org_id)
    
    saved_state_bytes = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    print(saved_state_bytes)
    if not saved_state_bytes:
        raise HTTPException(status_code=400, detail='No state found in Redis')

    saved_state_str = saved_state_bytes.decode()

    saved_state_data = json.loads(base64.urlsafe_b64decode(saved_state_str.encode()))

    if original_state != saved_state_data.get('state'):
        raise HTTPException(status_code=400, detail='State does not match')

    print("auth starting")
    async with httpx.AsyncClient() as client:
        response , _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'redirect_uri': REDIRECT_URI,
                    'code': code
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        )

        print("got creds" , response.json())

        await add_key_value_redis(f'hubspot_credential:{org_id}:{user_id}', json.dumps(response.json()) , expire=600)

        print("closing window")
        close_window_script = """
        <html>
            <script>
                 window.close();
            </script>
        </html>
        """
        print("window closed")
        return HTMLResponse(content=close_window_script)
        


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credential:{org_id}:{user_id}')
    print(credentials)
    if not credentials:
        raise HTTPException(status_code=400 , detail='No Credentails found .')
    
    credentials = json.loads(credentials)
    if not credentials:
        raise HTTPException(status_code=400 , detail='No Credentails found .')
    
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials


async def create_integration_item_metadata_object(response_json):
    # TODO
    pass

async def get_items_hubspot(credentials):
    # TODO
    pass