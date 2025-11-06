# Instructions

1. Do not make sweeping edits. Always make changes to one part of the code at a time, and clarify with the user before continuing
2. Do not make assumptions. If a piece of code doesn't correlate with the response, or a missing piece of information is needed, clarify with the user

## Connector Summary

The `default_gti_livehuntconnector.py` script is a Siemplify connector. Its primary role is to connect to the Google Threat Intelligence (GTI) API, formerly known as VirusTotal.

It fetches "Livehunt" notifications, which are threat alerts, from GTI. The connector processes these notifications, transforms them into Siemplify's `AlertInfo` format, and ingests them into the Siemplify SOAR platform for security operations and incident response.

## API Endpoint

The connector uses the following API endpoint to fetch Livehunt notifications:
`https://www.virustotal.com/api/v3/intelligence/hunting_notification_files`

---

## Development Plan: IOC Stream Integration

**Objective:** Update the connector to use the `/api/v3/ioc_stream` endpoint to ingest files, URLs, domains, and IP addresses.

**Development Process:**

1.  **Create Copies:** Do not edit the `default_gti_*.py` files directly. For each file that needs modification, create a copy prefixed with `dom_gti_`.
2.  **Preserve Original Code:** When making changes in the new `dom_gti_*.py` files, comment out the original code block instead of deleting it.
3.  **Add New Code:** Add the new, modified code directly below the commented-out block.
4.  **Add Comments:** Include a simple, descriptive comment (e.g., `# [MODIFIED] - ...`) above the new code to explain the change.

**Files to be Modified: Not exhaustive**

*   `default_gti_constants.py` -> `dom_gti_constants.py`
*   `default_gti_livehuntconnector.py` -> `dom_gti_livehuntconnector.py`
*   `default_gti_api_manager.py` -> `dom_gti_api_manager.py`
*   `default_gti_data_models.py` -> `dom_gti_data_models.py`
*   `default_gti_api_data_parser.py` -> `dom_gti_api_data_parser.py`
*   Update internal imports within the new `dom_gti_` files to point to each other.

---

## In-Progress

- **`dom_gti_constants.py`**: Updated `ENDPOINTS` to include `get_ioc_stream: "api/v3/ioc_stream"` and commented out the old `get_notifications` endpoint.
- **`dom_gti_data_models.py`**: Replaced the `Notification` dataclass with `IOCStreamObject` to handle diverse IOC types and their specific attributes from the new API. The old `Notification` class was commented out.
- **`dom_gti_api_data_parser.py`**:
    - Modified `get_next_page_url` to extract the `cursor` from the `meta` object.
    - Commented out the `build_notification_objects` function.
    - Added `build_ioc_stream_objects` function to parse responses into `IOCStreamObject` instances.
- **`dom_gti_api_manager.py`**:
    - Replaced the `get_notifications` method with `get_ioc_stream`, updating its endpoint, parameters, and parser to align with the new IOC stream.
    - Renamed and updated `_paginate_results_by_next_page_link` to `_paginate_results_by_cursor` to implement cursor-based pagination using the `meta.cursor` field.
