import json
from dataclasses import dataclass
import requests
from openai import OpenAI
from pydantic import BaseModel
import os
import time
from tqdm import tqdm  # Import tqdm for progress bar
import sqlite3

second = 0.1

system_prompt = """
You are an AI assistant tasked with analyzing API responses to determine if they violate the permission model described in the user's authorization description.
Remember, if a customer read only token can read billing information from the customer endpoints, it is still considered violating the permission.

Your analysis should be returned in JSON format, matching the following schema:

{
  "violatesIntendedPermission": bool,
  "violatedPermission": str,
  "analysis": str
}

- **violatesIntendedPermission**: Set to true if there is a violation of permission, such as a customer read only authentication can access billing information, false otherwise.
- **violatedPermission**: Briefly describe the permission that was violated, only return this when violatesIntendedPermission returns true
- **analysis**: Provide a detailed explanation of why the response does, only return this when violatesIntendedPermission returns true

Ensure that your response is a valid JSON object conforming to this schema.
"""

DB_FILE = "progress.db"

def initialize_db():
    """Initialize the SQLite database to store request and analysis progress."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Drop the table if it exists to start fresh
    cursor.execute("DROP TABLE IF EXISTS request_progress")
    cursor.execute("""
        CREATE TABLE request_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_auth_description TEXT,
            endpoint_method TEXT,
            endpoint_path TEXT,
            status_code INTEGER,
            response_body TEXT,
            request_completed BOOLEAN DEFAULT 0,
            analysis_result TEXT,
            violated BOOLEAN DEFAULT 0,
            analysis_completed BOOLEAN DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def save_response(auth_description, endpoint, status_code, response_body):
    """Save the API request response to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO request_progress (
            user_auth_description, endpoint_method, endpoint_path, 
            status_code, response_body, request_completed, analysis_completed
        ) VALUES (?, ?, ?, ?, ?, 1, 0)
    """, (auth_description, endpoint.method, endpoint.path, status_code, response_body))
    conn.commit()
    conn.close()

def get_pending_requests(user_auths, endpoints):
    """Get a list of requests not yet completed."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    completed_requests = cursor.execute("""
        SELECT user_auth_description, endpoint_method, endpoint_path 
        FROM request_progress WHERE request_completed = 1
    """).fetchall()
    conn.close()

    # Convert completed requests to a set for faster lookup
    completed_requests_set = set(completed_requests)

    # Identify pending requests
    pending_requests = [
        (auth, endpoint) for auth in user_auths for endpoint in endpoints
        if (auth.description, endpoint.method, endpoint.path) not in completed_requests_set
    ]

    # Debugging statements
    print("Completed Requests:", completed_requests)
    print("Pending Requests:", [(auth.description, endpoint.method, endpoint.path) for auth, endpoint in pending_requests])

    return pending_requests

def get_pending_analyses():
    """Get a list of responses that need analysis."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    pending = cursor.execute("""
        SELECT user_auth_description, endpoint_method, endpoint_path, 
               status_code, response_body 
        FROM request_progress WHERE request_completed = 1 AND analysis_completed = 0
    """).fetchall()
    conn.close()
    return pending

def save_analysis(auth_description, endpoint, analysis_result):
    """Save the analysis result to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE request_progress 
        SET violated = ?, analysis_result = ?, analysis_completed = 1
        WHERE user_auth_description = ? AND endpoint_method = ? AND endpoint_path = ?
    """, (analysis_result.violatesIntendedPermission, json.dumps(analysis_result.dict()), auth_description, endpoint.method, endpoint.path))
    conn.commit()
    conn.close()

class PermissionViolation(BaseModel):
  violatesIntendedPermission: bool
  violatedPermission: str
  analysis: str

@dataclass
class UserAuth:
    headers: dict
    description: str

@dataclass
class Endpoint:
    method: str
    path: str

def load_configuration(config_file: str):
    with open(config_file, 'r') as f:
        config = json.load(f)
    host = config['host']
    user_auths = [UserAuth(**ua) for ua in config['user_auth']]
    endpoints = [Endpoint(**ep) for ep in config['endpoints']]
    return host, user_auths, endpoints


def generate_report():
    """Generate a report from the analysis results."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    results = cursor.execute("""
        SELECT user_auth_description, endpoint_method, endpoint_path, analysis_result 
        FROM request_progress WHERE analysis_completed = 1
    """).fetchall()
    conn.close()

    report = f"Total Requests Analyzed: {len(results)}\n\n"
    report += "Details of Analysis:\n"
    for auth_description, method, path, analysis_result in results:
        analysis = json.loads(analysis_result)
        report += f"- User: {auth_description}\n"
        report += f"  Endpoint: {method} {path}\n"
        report += f"  Analysis: {analysis}\n\n"
    return report


def make_requests(host, user_auths, endpoints):
    """Make API requests and save progress."""
    pending_requests = get_pending_requests(user_auths, endpoints)
    total_requests = len(pending_requests)

    with tqdm(total=total_requests, desc="Processing API Requests", ncols=100) as pbar:
        for auth, endpoint in pending_requests:
            url = f"{host}{endpoint.path}"
            headers = auth.headers
            method = endpoint.method.upper()

            try:
                print(f"Making request to {url} with {auth.description}...")
                response = requests.request(method, url, headers=headers)
                status_code = response.status_code
                response_body = response.text
            except Exception as e:
                status_code = None
                response_body = str(e)

            # Save the response and mark the request as completed
            save_response(auth.description, endpoint, status_code, response_body)

            # Update the progress bar
            pbar.update(1)
            print(f"Waiting for {second} seconds...")
            time.sleep(second)

def analyze_responses(client):
    """Analyze pending responses and save the results."""
    pending_responses = get_pending_analyses()

    # with tqdm(total=total_analyses, desc="Analyzing Responses", ncols=100) as pbar:
    for auth_description, method, path, status_code, response_body in pending_responses:
        if status_code == 403 or status_code == 404:
            continue
        user_prompt = f"""
        User Authorization Description:
        {auth_description}

        API Endpoint Called:
        Method: {method}
        Path: {path}

        Status Code:
        {status_code}

        Response Body:
        {response_body}

        Please analyze whether the above response violates the permission model described in the user's authorization description and provide your findings in the specified JSON format.
        """
        try:
            response = client.beta.chat.completions.parse(
                model="gpt-4o-2024-08-06",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0,
                response_format=PermissionViolation
            )
            parsed_response = response.choices[0].message.parsed
            # is_violated = parsed_response.violatesIntendedPermission
            # violatedPermission = parsed_response.violatedPermission
            # analysis = parsed_response.analysis
            # full_analysis = str(is_violated) + violatedPermission + analysis

            save_analysis(auth_description, Endpoint(method, path), parsed_response)
        except Exception as e:
            print(f"Error analyzing response: {e}")
            continue  # Skip to the next response if an error occurs

            # Update the progress bar
            # pbar.update(1)

def main():
    initialize_db()  # Ensure the database is initialized
    api_key = os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=api_key)
    config_file = 'configuration.json'  # Path to your configuration file
    host, user_auths, endpoints = load_configuration(config_file)
    make_requests(host, user_auths, endpoints)
    analyze_responses(client)
    report = generate_report()
    print(report)
    # Optionally, write the report to a file
    with open('report.txt', 'w') as f:
        f.write(report)

if __name__ == "__main__":
    main()