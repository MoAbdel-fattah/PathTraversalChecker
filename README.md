# PathTraversalChecker
This script checks for path traversal vulnerabilities in a given URL by testing various payloads. It prints the results in green if a vulnerability is found and in red if not. At the end, it provides a summary of the total vulnerabilities found and the payloads that worked.

![Watch the video](https://github-production-user-asset-6210df.s3.amazonaws.com/114058415/369674611-bac19f2a-d8af-4b4b-b540-68d7fdbf8db9.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240922%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240922T083110Z&X-Amz-Expires=300&X-Amz-Signature=f11b10eddbf936ca5115579482196e190186a900a0e0a23d4cf4852b02cc08d2&X-Amz-SignedHeaders=host)

## Prerequisites

- Python 3.x
- `requests` library
- `colorama` library

You can install the required libraries using pip:

```sh
pip install requests colorama | pip install requests
```

## Usage
Run the script from the terminal and pass the URL as a command-line argument:
```sh
python Path_Traversal_Checker.py <url>
```
### Example:
```sh
python Path_Traversal_Checker.py https://example.com/image?filename
```

## Script Details
The script performs the following steps:

- Parse the URL: Identifies potential entry points in the URL query parameters.
- Payloads: Uses a comprehensive list of payloads (both encoded and unencoded) to test for path traversal vulnerabilities.
- Send Requests: Constructs request URLs with the payloads and sends them to the target URL.
- Analyze Responses: Checks the response for indicators of a successful path traversal attack (e.g., presence of “root:x:” or “boot loader”).
- Print Results: Outputs the results in green if a vulnerability is found and in red if not.
- Summary: Prints a summary of the total vulnerabilities found and the payloads that worked.
```sh
Example Output
Testing URL: https://example.com/image?filename=../../../etc/passwd
No vulnerability found with payload: ../../../etc/passwd
Testing URL: https://example.com/image?filename=../../../../../etc/passwd
Vulnerability found with payload: ../../../../../etc/passwd

Summary:
Total vulnerabilities found: 1
Payloads that worked:
../../../../../etc/passwd

Final Summary:
Total Payloads that worked: 1
Payloads that worked:
../../../../../etc/passwd
```

## Notes
- Ensure you have permission to test the target URL for vulnerabilities.
- The script checks for specific strings in the response that are commonly found in sensitive files. Adjust the indicators as needed for your specific use case.

## License
- This project is licensed under the MIT License.
