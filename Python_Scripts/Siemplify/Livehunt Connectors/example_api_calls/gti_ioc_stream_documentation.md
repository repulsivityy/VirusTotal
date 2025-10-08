# Get objects from the IoC Stream
get https://www.virustotal.com/api/v3/ioc\_stream

The IoC stream endpoint returns different types of objects (files, URLs, domains, IP addresses) coming from multiple origins (you can restrict the returned types by using the filters explained below). In addition, depending on the origin of the notification there will be different context attributes added to these objects.

The possible context attributes in IoC Stream objects are:

*   `notification_id`: <_string_\> Always present. This string identifies the notification, and can be used to retrieve the notification individually (by using [GET /ioc\_stream\_notifications/{id}](https://gtidocs.virustotal.com/reference/get-an-ioc-stream-notification)) or to delete it ([DELETE /ioc\_stream\_notifications/{id}](https://gtidocs.virustotal.com/reference/delete-an-ioc-stream-notification)).
*   `notification_date`: <_int_\> Always present. Date when the notification was created (UTC timestamp).
*   `origin`: <_string_\> Always present. The notification's origin. In the case of Livehunt or Retrohunt the origin is `hunting`.
*   `sources`: <_list of dictionaries_\> Always present. The different sources associated to the notification. In the case of Livehunt the only source is always the hunting ruleset that triggered the notification.
*   `tags`: <_list of strings_\> List of notification's tags (if any). These tags can be used to filter the objects by using the `notification_tag:` filter.
*   `hunting_info`: <_dictionary_\> Only present for notifications of `hunting` origin. It contains additional contextual information from Livehunt. Its structure is the following:
    *   `rule_name`: <_string_\> matched rule name.
    *   `rule_tags`: <_list of strings_\> matched rule tags.
    *   `snippet`: <_string_\> matched contents inside the file as hexdump. Contains `begin_highlight` and `end_highlight` substrings to indicate the part of the file that produced the match and give additional context about surrounding bytes in the match.
    *   `source_country`: <_string_\> country where the matched file was uploaded from.
    *   `source_key`: <_string_\> unique identifier for the source in ciphered form.

Allowed filters with examples (they can be combined in the same filter string):

*   `date:2023-02-07T10:00:00+`: Returns objects from notifications generated after 2023-02-07T10:00:00 (UTC)
*   `date:2023-02-07-`: Returns objects from notifications generated before 2023-03-07T00:00:00 (UTC)
*   `origin:hunting`: Returns objects from notifications coming from Livehunt. Allowed values: `hunting, subscriptions`.
*   `entity_id:objectId`: Return objects whose ID is `objectId`
*   `entity_type:file`: Return only file objects. Allowed values: `file, domain, url, ip_address`
*   `source_type:hunting_ruleset`: The type of source object that triggered the notification. Allowed values: `hunting_ruleset, retrohunt_job, collection, threat_profile`.
*   `source_id:objectId`: The ID of the source object that triggered the notification. In the case of hunting the notification's source object ID corresponds to the hunting ruleset's ID.
*   `notification_tag:ruleName`: Notifications with `ruleName` in their tags. In the case of notifications coming from Livehunt there are several tags in each notification, like the rule name or the username of the ruleset's owner.

Allowed orders:

*   `date-` (default): Sorts by most recent notifications first.
*   `date+`: Sorts by oldest notification first.

