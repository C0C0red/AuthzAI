# AuthzAI

An automated tool to test and analyze API endpoints for potential permission model violations using OpenAI structured outputs.

## Introduction

**AuthzAI** is a Python script designed to automate the process of testing API endpoints with various user authentications and analyzing the responses to detect any violations of the intended permission model. It will interpret API responses and identify potential security issues related to permissions.

This tool is especially useful for developers and bug bounty hunters who want to ensure that automate the process of permission testing.

## Features

- **Automated API Requests**: Sends requests to specified endpoints using different user authentication headers.
- **Permission Analysis**: Uses OpenAI's GPT models to analyze API responses for permission violations.
- **Progress Tracking**: Stores request and analysis progress in a SQLite database (`progress.db`).
- **Comprehensive Reporting**: Generates a basic report (`report.txt`) summarizing the analysis results.
- **Customizable Configuration**: Easily configure hosts, user authentications, and endpoints via a JSON file.

## Installation

### Prerequisites

- Python 3.7 or higher
- An OpenAI API key (sign up [here](https://platform.openai.com/))

### Clone the Repository

```bash
git clone https://github.com/ngalongc/AuthzAI
cd AuthzAI
```

### Install Dependencies

Install the required Python packages using `pip`:

```bash
pip install -r requirements.txt
```

**Contents of `requirements.txt`:**

```
requests
openai
pydantic
tqdm
```

### Set Up OpenAI API Key

Set your OpenAI API key as an environment variable:

- On Unix/Linux:

  ```bash
  export OPENAI_API_KEY='your-api-key-here'
  ```

- On Windows:

  ```cmd
  set OPENAI_API_KEY='your-api-key-here'
  ```

Replace `'your-api-key-here'` with your actual OpenAI API key.

## Configuration

Create a `configuration.json` file in the root directory to define your API host, user authentications, and endpoints to test.

**Sample `configuration.json`:**

```json
{
  "host": "https://api.example.com",
  "user_auth": [
    {
      "headers": {
        "Authorization": "Bearer admin_token"
      },
      "description": "Admin user with full permissions."
    },
    {
      "headers": {
        "Authorization": "Bearer read_only_token"
      },
      "description": "Read-only user with limited permissions."
    }
  ],
  "endpoints": [
    {
      "method": "GET",
      "path": "/v1/account/details"
    },
    {
      "method": "POST",
      "path": "/v1/account/update"
    },
    {
      "method": "GET",
      "path": "/v1/billing/info"
    }
  ]
}
```

### Configuration Parameters

- **host**: The base URL of your API.
- **user_auth**: A list of user authentication objects.
  - **headers**: A dictionary of HTTP headers (e.g., `Authorization` tokens).
  - **description**: A description of the user's permissions.
- **endpoints**: A list of API endpoints to test.
  - **method**: The HTTP method (currently only supports `GET`)
  - **path**: The endpoint path relative to the host.

## Usage

Run the script using Python:

```bash
python authz_ai.py
```

### What Happens When You Run the Script

1. **Database Initialization**: Sets up a SQLite database (`progress.db`) to store progress.
2. **Configuration Loading**: Reads the `configuration.json` file.
3. **API Requests**: Makes requests to each endpoint with each user authentication.
4. **Response Saving**: Saves responses to the database.
5. **Response Analysis**: Analyzes responses using OpenAI's GPT models to detect permission violations.
6. **Result Saving**: Saves analysis results back to the database.
7. **Report Generation**: Creates a `report.txt` file summarizing the findings.

### Adjusting the Request Delay

By default, the script waits for 0.1 seconds between requests. You can adjust this by changing the `second` variable in the script:

```python
second = 0.1  # Adjust the delay as needed
```

## Output

- **progress.db**: A SQLite database file storing requests and analysis progress.
- **report.txt**: A text file summarizing the analysis results.

**Sample `report.txt`:**

```
Total Requests Analyzed: 6

Details of Analysis:
- User: Admin user with full permissions.
  Endpoint: GET /v1/account/details
  Analysis: No permission violations detected.

- User: Read-only user with limited permissions.
  Endpoint: POST /v1/account/update
  Analysis:
  {
    "violatesIntendedPermission": true,
    "violatedPermission": "Modification of account details by a read-only user.",
    "analysis": "The read-only user should not be able to update account details, but the response indicates success."
  }

...
```

## Troubleshooting

- **OpenAI API Errors**: Ensure your OpenAI API key is correct and you have sufficient quota.
- **Configuration Errors**: Double-check your `configuration.json` for correct syntax and valid endpoints.
- **Database Issues**: If you encounter database errors, delete `progress.db` to reset.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the GNU Affero General Public License v3.0.

## Acknowledgments

- [OpenAI](https://openai.com/) for providing the GPT models.
- [Pydantic](https://pydantic-docs.helpmanual.io/) for data validation.
- [tqdm](https://tqdm.github.io/) for the progress bars.
- [SQLite](https://www.sqlite.org/index.html) for the database.

## Contact

For any questions or suggestions, feel free to open an issue or DM me on X @ngalongc.