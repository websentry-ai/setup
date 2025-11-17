#!/usr/bin/env python3

import sys
import json
import os
import urllib.request
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional


UNBOUND_GATEWAY_URL = "https://api.getunbound.ai"
AUDIT_LOG = Path.home() / ".claude" / "hooks" / "agent-audit.log"


def load_existing_logs() -> List[Dict]:
    logs = []
    if AUDIT_LOG.exists():
        try:
            with open(AUDIT_LOG, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            logs.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception:
            pass
    return logs


def save_logs(logs: List[Dict]):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, 'w', encoding='utf-8') as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
    except Exception:
        pass


def append_to_audit_log(event_data: Dict):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event_data) + '\n')
    except Exception:
        pass


def parse_transcript_file(transcript_path: str, user_prompt_timestamp: Optional[str] = None) -> Dict:
    conversation_data = {
        'user_messages': [],
        'assistant_messages': [],
        'tool_uses': []
    }
    
    if not transcript_path or not os.path.exists(transcript_path):
        return conversation_data
    
    try:
        with open(transcript_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                    
                try:
                    entry = json.loads(line)
                    entry_type = entry.get('type', '')
                    entry_timestamp = entry.get('timestamp')
                    
                    if entry_type == 'user':
                        message = entry.get('message', {})
                        if message.get('role') == 'user':
                            content = message.get('content', '')
                            if content:
                                conversation_data['user_messages'].append({
                                    'content': content,
                                    'timestamp': entry_timestamp
                                })
                    
                    elif entry_type == 'assistant':
                        if user_prompt_timestamp and entry_timestamp:
                            if entry_timestamp <= user_prompt_timestamp:
                                continue
                        
                        message = entry.get('message', {})
                        if message.get('role') == 'assistant':
                            content_array = message.get('content', [])
                            text_content = ''
                            for content_item in content_array:
                                if isinstance(content_item, dict) and content_item.get('type') == 'text':
                                    text_content = content_item.get('text', '')
                                    if text_content:
                                        conversation_data['assistant_messages'].append({
                                            'content': text_content,
                                            'timestamp': entry_timestamp
                                        })
                        
                except json.JSONDecodeError:
                    continue
                    
    except Exception:
        pass
    
    return conversation_data


def build_llm_exchange(events: List[Dict], main_transcript_data: Optional[Dict] = None) -> Optional[Dict]:
    messages = []
    assistant_tool_uses = []
    all_assistant_responses = []
    
    user_prompt = None
    user_prompt_timestamp = None
    session_id = None
    
    for log_entry in events:
        event = log_entry.get('event', {}) if 'event' in log_entry else log_entry
        if event.get('hook_event_name') == 'UserPromptSubmit':
            user_prompt = event.get('prompt')
            user_prompt_timestamp = log_entry.get('timestamp')
            break
    
    if main_transcript_data and user_prompt_timestamp:
        for assistant_msg in main_transcript_data.get('assistant_messages', []):
            msg_timestamp = assistant_msg.get('timestamp')
            content = assistant_msg.get('content', '')
            
            if msg_timestamp and msg_timestamp > user_prompt_timestamp:
                if content:
                    all_assistant_responses.append(content)
    
    for log_entry in events:
        event = log_entry.get('event', {}) if 'event' in log_entry else log_entry
        hook_event_name = event.get('hook_event_name')
        
        if not session_id:
            session_id = event.get('session_id')
        
        if hook_event_name == 'UserPromptSubmit':
            prompt = event.get('prompt')
            if prompt:
                user_prompt = prompt
        
        elif hook_event_name == 'PostToolUse':
            tool_name = event.get('tool_name')
            tool_input = event.get('tool_input', {})
            tool_response = event.get('tool_response', {})
            
            if 'content' in tool_response and 'content' in tool_input:
                if tool_response['content'] == tool_input['content']:
                    tool_response = {k: v for k, v in tool_response.items() if k != 'content'}
            
            assistant_tool_uses.append({
                'type': 'PostToolUse',
                'tool_name': tool_name,
                'tool_input': tool_input,
                'tool_response': tool_response
            })
    
    assistant_response = '\n\n'.join(all_assistant_responses) if all_assistant_responses else ""
    
    if user_prompt:
        messages.append({'role': 'user', 'content': user_prompt})
    
    if assistant_response or assistant_tool_uses:
        assistant_msg = {
            'role': 'assistant',
            'content': assistant_response
        }
        
        if assistant_tool_uses:
            assistant_msg['tool_use'] = assistant_tool_uses
        
        messages.append(assistant_msg)
    elif user_prompt and assistant_tool_uses:
        assistant_msg = {
            'role': 'assistant',
            'content': "",
            'tool_use': assistant_tool_uses
        }
        messages.append(assistant_msg)
    
    if len(messages) == 1 and messages[0]['role'] == 'user':
        return None
    
    if not messages:
        return None
    
    exchange = {
        'conversation_id': session_id or 'unknown',
        'model': 'auto',
        'messages': messages
    }
    
    return exchange


def send_to_api(exchange: Dict, api_key: str) -> bool:
    if not api_key:
        return False
    
    try:
        url = f"{UNBOUND_GATEWAY_URL}/v1/hooks/claude"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        data = json.dumps(exchange).encode('utf-8')
        request = urllib.request.Request(url, data=data, headers=headers, method='POST')
        
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status == 200
            
    except Exception:
        return False


def cleanup_old_logs():
    logs = load_existing_logs()
    
    if len(logs) <= 50:
        return
    
    session_order = []
    seen_sessions = set()
    
    for log in logs:
        session_id = log.get('session_id')
        if session_id and session_id not in seen_sessions:
            session_order.append(session_id)
            seen_sessions.add(session_id)
    
    if len(session_order) > 1:
        most_recent_session = session_order[-1]
        kept_logs = [
            log for log in logs
            if log.get('session_id') == most_recent_session
        ]
        save_logs(kept_logs)


def process_stop_event(event: Dict, api_key: str):
    session_id = event.get('session_id')
    transcript_path = event.get('transcript_path')
    
    logs = load_existing_logs()
    
    session_events = []
    current_conversation_started = False
    user_prompt_timestamp = None
    
    for log in logs:
        log_session_id = log.get('session_id') or log.get('event', {}).get('session_id')
        
        if log_session_id == session_id:
            event_name = log.get('event', {}).get('hook_event_name') if 'event' in log else log.get('hook_event_name')
            
            if event_name == 'UserPromptSubmit':
                session_events = [log]
                current_conversation_started = True
                user_prompt_timestamp = log.get('timestamp')
            elif current_conversation_started:
                session_events.append(log)
    
    main_transcript_data = None
    if transcript_path and transcript_path != 'undefined':
        main_transcript_data = parse_transcript_file(transcript_path, user_prompt_timestamp)
    
    exchange = build_llm_exchange(session_events, main_transcript_data)
    
    if exchange:
        success = send_to_api(exchange, api_key)
        
        if success:
            remaining_logs = [
                log for log in logs
                if log.get('session_id') != session_id and
                (not log.get('event') or log.get('event', {}).get('session_id') != session_id)
            ]
            save_logs(remaining_logs)


def main():
    api_key = os.getenv('UNBOUND_CLAUDE_API_KEY')
    
    try:
        input_data = sys.stdin.read().strip()
        
        if not input_data:
            print("{}", flush=True)
            return
        
        try:
            event = json.loads(input_data)
        except json.JSONDecodeError:
            print("{}", flush=True)
            return
        
        timestamp = datetime.utcnow().isoformat() + 'Z'
        log_entry = {
            'timestamp': timestamp,
            'session_id': event.get('session_id'),
            'event': event
        }
        
        append_to_audit_log(log_entry)
        
        hook_event_name = event.get('hook_event_name')
        session_id = event.get('session_id')
        
        if hook_event_name == 'Stop' and session_id:
            process_stop_event(event, api_key)
        
        cleanup_old_logs()
        
        print("{}", flush=True)
        
    except Exception as e:
        # Still return empty JSON object to Claude Code to indicate completion
        print("{}", flush=True)


if __name__ == '__main__':
    main()