For authenticating with the API you must include the x-apikey header with your personal API key in all your requests. Your API key can be found in your VirusTotal account user menu:


Your API key carries all your privileges, so keep it secure and don't share it with anyone. Always use HTTPS instead of HTTP for making your requests.

Errors
The VirusTotal API follows the conventional HTTP response codes to indicate success or failure. Codes in the 2xx range indicate success. Codes in the 4xx range indicate an error in the request (e.g. a missing parameter, a resource was not found). Codes in the 5xx range indicate an error in VirusTotal's servers and should be rare.

Unsuccessful requests return additional information about the error in JSON format.

An error response
Example (404)
Example (401)

{
  "error": {
    "code": "<error code>",
    "message": "<a message describing the error>"
  }
}
The error code is a string with one of the values provided in the table below. The message usually provides a little more information about the error.
HTTP Code	Error code	Description
400	BadRequestError	The API request is invalid or malformed. The message usually provides details about why the request is not valid.
400	InvalidArgumentError	Some of the provided arguments are incorrect.
400	NotAvailableYet	The resource is not available yet, but will become available later.
400	UnselectiveContentQueryError	Content search query is not selective enough.
400	UnsupportedContentQueryError	Unsupported content search query.
401	AuthenticationRequiredError	The operation requires an authenticated user. Verify that you have provided your API key.
401	UserNotActiveError	The user account is not active. Make sure you properly activated your account by following the link sent to your email.
401	WrongCredentialsError	The provided API key is incorrect.
403	ForbiddenError	You are not allowed to perform the requested operation.
404	NotFoundError	The requested resource was not found.
409	AlreadyExistsError	The resource already exists.
424	FailedDependencyError	The request depended on another request and that request failed.
429	QuotaExceededError	You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC.
You may have run out of disk space and/or number of files on your VirusTotal Monitor account.
429	TooManyRequestsError	Too many requests.
503	TransientError	Transient server error. Retry might work.
504	DeadlineExceededError	The operation took too long to complete.

Key concepts
The VirusTotal API v3 revolves around three key concepts: objects, collections and relationships.

An object is any item that can be retrieved or manipulated using the API. Files, URLs, domain names and VT Hunting rulesets are some of the object types exposed by the API.

A collection is a set of objects. Objects in a collection are usually of the same type, but there are a few exceptions to that rule. Some API operations are performed on objects, while some others are performed on collections.

Relationships are links between objects, for example: a file can be related to another file because one of them is a ZIP that contains the other, a URL can be related to a file because the file was downloaded from the URL, a domain name is related to all the URLs on that domain.

Objects
Objects are a key concept in the VirusTotal API. Each object has an identifier and a type. Identifiers are unique among objects of the same type, which means that a (type, identifier) pair uniquely identifies any object across the API. In this documentation, those (type, identifier) pairs are referred as object descriptors.

Each object has an associated URL with the following structure:


https://www.virustotal.com/api/v3/{collection name}/{object id}
Usually {collection name} is the plural form of the object type, for example, files is the collection containing all the objects of type file, and analyses is the collection containing all the analysis objects. The format for {object id} varies from one object type to another.

A GET request to the object's URL returns information about the object in the following format:

Example response

{
  "data": {
    "type": "{object type}",
    "id": "{object id}",
    "links": {
      "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}"
    },
    "attributes" : {
      "integer_attribute": 1234,
      "string_attribute": "this is a string",
      "dictionary_attribute": { "one": 1, "two": 2 },
      "list_attribute": [ "foo", "bar", "baz" ]
    },
    "relationships" : {
       ..
    }
  } 
}
Besides an ID and a type, the object has a set of attributes and relationships. Attributes can be of any type supported by JSON, including lists and dictionaries. The attributes field is always present in all objects, but relationships is optional, depending on whether or not you asked for relationships to be included while making your request. This will discussed in depth in the Relationships section.

Each object type has its own pre-defined set of attributes, you won't be able to add nor remove attributes, you can only modify existing ones (as long as they are writable). To modify an object's attributes you must send a PATCH request to the object's URL. If you try to modify a read-only attribute you will get an error. The PATCH request's body must contain the attributes you want to modify in a structure like the one shown in the example below. Any attribute not included in the request will remain unchanged.

Example PATCH request

{
  "data": {
    "type": "{object type}",
    "id": "{object id}",
    "attributes" : {
      "integer_attribute": 1234,
      "string_attribute": "this is a new string",
    }
  } 
}
Notice that both the object's ID and type are included in the PATCH request's body, and they must match those specified in the URL.

Some object types can be also deleted by sending a DELETE request to the object's URL.

Collections
Collections are sets of objects. For most object types there is a top-level collection representing all objects of that type. Those collections can be accessed by using a URL like:


https://www.virustotal.com/api/v3/{collection name}
Many operations in the VirusTotal API are performed by sending requests to a collection. For example, you can analyse a file by sending a POST request to /api/v3/files, which effectively adds a new item to the files collection. You can create a new VT Hunting ruleset by sending a POST request to /api/v3/intelligence/hunting_rulesets. Sending a POST request to a collection is usually the way in which new objects are created.

Similarly, a DELETE request sent to a collection has the effect of deleting all objects in that collection. As you may imagine, there's no DELETE method for certain collections like files, urls or analyses, but you can use DELETE on other collection types such as hunting_notifications to remove all your VT Hunting notifications.

Many collections are also iterable, you can retrieve all objects in the collection by sending successive GET requests to the collection. On each request you get a number of objects and a cursor that is used to continue the iteration. The snippet below exemplifies the response from a GET request to /api/v3/{collection name}.

Example collection response

{
    "data": [
      { .. object 1 .. },
      { .. object 2 .. },
      { .. object 3 .. }
    ],
    "meta": {
      "cursor": "CuABChEKBGRhdGUSCQjA1.."
    },
    "links": {
        "next": "https://www.virustotal.com/api/v3/{collection name}?cursor=CuABChEKBGRhdGUSCQjA1..",
        "self": "https://www.virustotal.com/api/v3/{collection name}"
    }
}
As the next field in the links section suggest, you can use the cursor in the response's metadata as a parameter in a subsequent call for retrieving the next set of objects. You can also use the limit parameter for controlling how many objects are returned on each call.

Relationships
Relationships are the way in which the VirusTotal API expresses links or dependencies between objects. An object can be related to objects of the same or a different type. For example, a file object can be related to some other file object that contains the first one, or a file object can be related to URL objects representing the URLs embedded in the file.

Relationships can be one-to-one or one-to-many, depending of whether the object is related a single object or to multiple objects.

When retrieving a particular object with a GET request you may want to retrieve its relationships with other objects too. This can be done by specifying the relationship you want to retrieve in the relationships parameter.


https://www.virustotal.com/api/v3/{collection name}/{object id}?relationships={relationship}
More than one relationship can be included in the response by specifying a comma-separated list of relationship names.


https://www.virustotal.com/api/v3/{collection name}/{object id}?relationships={relationship 1},{relationship 2}
The objects returned by such requests include the relationships dictionary, where keys are the names of the requested relationships, and values are either an object descriptor (if the relationship is one-to-one) or a collection as described in the Collections section (if the relationship is one-to-many). Notice however that these collections don't contain the whole related objects but only their descriptors (i.e: their type and ID).

Relationships in an object

{
  "type": "{object type}",
  "id": "{object id}",
  "links": {
    "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}"
  },
  "attributes" : {
     ..
  },
  "relationships" : {
     "{one-to-one relationship}": {
       "data": {
         "id": "www.google.com",
         "type": "domain"
       },
       "links": {
         "related": "https://www.virustotal.com/api/v3/{collection name}/{object id}/{one-to-one relationship}",
         "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{one-to-one relationship}"
       }
     },
     "{one-to-many relationship}": {
       "data": [
         { .. object descriptor 1 .. },
         { .. object descriptor 2 .. },
         { .. object descriptor 3 .. }
       ],
       "meta": {
         "cursor": "CuABChEKBGRhdGUSCQjA1LC...",
       },
       "links": {
         "next": "https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{one-to-many relationship}?cursor=CuABChEKBGRhdGUSCQjA1LC...",
         "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{one-to-many relationship}"
       },
     },
    "{relationship 2}": { ... },
    "{relationship 3}": { ... }
  }
}
If you take a closer look to the links field for the relationship in the example above, you'll see that the self URL looks like:


https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{relationship}
One-to-many relationships are simply collections that contains objects that are somehow related to a primary object, so they usually have their own URL that you can use to iterate over the related objects by sending GET requests to the URL as described in the Collections section. Actually, there are two types of URLs:


https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{relationship}
https://www.virustotal.com/api/v3/{collection name}/{object id}/{relationship}
The first one is a collection that contains only the descriptors (type and ID) for the related objects, the second one contains the complete objects, with all their attributes. If you are interested only in the type and ID of the related objects you should use the first one, as it's more efficient to retrieve only the descriptors than the complete objects.

Another important difference between both endpoints is that {object id}/relationships/{relationship} represents the relationship, as an independent entity, and can support operations that change the relationship without altering the objects. On the other hand, {object id}/{relationship} is representing the related objects, not the relationship. For example, if you want to grant a user viewing permissions to a Graph, you use:


POST https://www.virustotal.com/api/v3/graphs/{id}/relationships/viewers
This endpoint receives a user descriptor, it doesn't modify the user nor the graph, it simply creates a relationship between them. On the other hand, when you create a new comment for a file you use:


POST https://www.virustotal.com/api/v3/files/{id}/comments
Because in this case you are not only modifying the relationship between a file and a comment, you are also creating a new comment object.

Relationships with objects not present in VirusTotal's database
For a variety of reasons, an object might be related to another object not present in our database. In those cases, the returned relationship will just contain the element ID and a "NotFoundError" error code.

NotFoundError in relationships

{
  "data": [
    {
      "error": {
        "code": "NotFoundError",
        "message": "{item type} with id \"{item id}\" not found"
      },
      "id": "{item id}",
      "type": "{item type}"
    },
    { .. object 2 .. },
    ...
  ],
  "links": {
    "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}/{one-to-many relationship}"
  }
}
When only object descriptors are requested (that is, requesting /api/v3/{collection name}/{object id}/**relationships**/{relationship name} instead of `/api/v3/{collection name}/{object id}/{relationship name}) this error is not returned.

Files
Files are one of the most important type of objects in the VirusTotal API. We have a huge dataset of more than 2 billion files that has been analysed by VirusTotal over the years. This section comprehends the API endpoints for analyzing new files and retrieving information about any file in our dataset.

Upload a file
post
https://www.virustotal.com/api/v3/files
Upload and analyse a file

📘
File size

If the file to be uploaded is bigger than 32MB, please use the /files/upload_url endpoint instead which admits files up to 650MB.

Body Params
File to scan

file
file
No file chosen
password
string
Optional, password to decompress and scan a file contained in a protected ZIP file.

Headers
x-apikey
string
required
Your API key

Responses

200
The analysis ID. Use /analyses/<analysis_ID> API call to check the analysis status.

400
If password was provided and the file isn't a ZIP, it contains more than one file, the password is incorrect, or the file is corrupt.

import virustotal from '@api/virustotal';

virustotal.postFiles()
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  {
  "data": {
    "type": "analysis",
    "id": "OTFiMDcwMjVjZDIzZTI0NGU4ZDlmMjI2NjkzZDczNGE6MTY1MzY1NDM3Nw=="
  }
}

Get a file report
get
https://www.virustotal.com/api/v3/files/{id}
Retrieve information about a file

Returns a File object.

Metadata
id
string
required
SHA-256, SHA-1 or MD5 identifying the file

x-apikey
string
required
Your API key

Responses

200
200

Response body
json

400
400

import virustotal from '@api/virustotal';

virustotal.fileInfo({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get comments on a file
get
https://www.virustotal.com/api/v3/files/{id}/comments
Returns a list of Comment objects.

Metadata
id
string
required
SHA-256, SHA-1 or MD5 identifying the file

limit
int32
Defaults to 10
Maximum number of comments to retrieve

10
cursor
string
Continuation cursor

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.filesCommentsGet({limit: '10', id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));


  Get objects related to a file
get
https://www.virustotal.com/api/v3/files/{id}/{relationship}
File objects have many relationships to other files and objects. As mentioned in the Relationships section, those related objects can be retrieved by sending GET requests to the relationship URL.

Some relationships are accessible only to users who have access to VirusTotal Enterprise package.

More common relationships are described in the File object documentation and you can use the metadata endpoint to get the full list of relationships.

Metadata
id
string
required
SHA-256, SHA-1 or MD5 identifying the file

relationship
string
required
Relationship name (see table)

limit
int32
Defaults to 10
Maximum number of related objects to retrieve

10
cursor
string
Continuation cursor

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.filesRelationships({limit: '10', id: 'id', relationship: 'relationship'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get object descriptors related to a file
get
https://www.virustotal.com/api/v3/files/{id}/relationships/{relationship}
This endpoint is the same as /files/{id}/{relationship} except it returns just the related object's IDs (and context attributes, if any) instead of returning all attributes.

Metadata
id
string
required
SHA-256, SHA-1 or MD5 identifying the file

relationship
string
required
Relationship name (see table)

limit
string
Defaults to 10
Maximum number of related objects to retrieve

10
cursor
string
Continuation cursor

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.filesRelationshipsIds({limit: '10', id: 'id', relationship: 'relationship'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get a crowdsourced Sigma rule object
get
https://www.virustotal.com/api/v3/sigma_rules/{id}
Returns a Sigma Rule object.

Metadata
id
string
required
Rule ID

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.getSigmaRules({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get a crowdsourced YARA ruleset
get
https://www.virustotal.com/api/v3/yara_rulesets/{id}
Yara Ruleset used in our crowdsourced YARA results.

Returns a YARA Ruleset object.

Metadata
id
string
required
Ruleset ID to fetch.

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.getYaraRulesets({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get a summary of all behavior reports for a file
get
https://www.virustotal.com/api/v3/files/{id}/behaviour_summary
This endpoint returns a summary with behavioural information about the file. The summary consists in merging together the reports produced by the multiple sandboxes we have integrated in VirusTotal.

This API call returns all fields contained in the File behaviour object, except the ones that make sense only for individual sandboxes:

analysis_date
behash
has_html_report
has_pcap
last_modification_date
sandbox_name
Example response

{
    "data": {
        "calls_highlighted": [
            "GetTickCount"
        ],
        "files_opened": [
            "C:\\WINDOWS\\system32\\winime32.dll",
            "C:\\WINDOWS\\system32\\ws2_32.dll",
            "C:\\WINDOWS\\system32\\ws2help.dll",
            "C:\\WINDOWS\\system32\\psapi.dll",
            "C:\\WINDOWS\\system32\\imm32.dll",
            "C:\\WINDOWS\\system32\\lpk.dll",
            "C:\\WINDOWS\\system32\\usp10.dll",
            "C:\\WINDOWS\\WinSxS\\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\\comctl32.dll",
            "C:\\WINDOWS\\system32\\winmm.dll",
            "C:\\WINDOWS\\system32\\winspool.drv",
            "C:\\WINDOWS\\WindowsShell.Manifest",
            "C:\\WINDOWS\\system32\\shell32.dll",
            "C:\\WINDOWS\\system32\\MSCTF.dll"
        ],
        "modules_loaded": [
            "comctl32.dll",
            "C:\\WINDOWS\\system32\\ws2_32.dll",
            "C:\\WINDOWS\\system32\\MSCTF.dll",
            "version.dll",
            "C:\\WINDOWS\\system32\\msctfime.ime",
            "C:\\WINDOWS\\system32\\ole32.dll",
            "USER32.dll",
            "IMM32.dll",
            "C:\\WINDOWS\\system32\\user32.dll"
        ],
        "mutexes_created": [
            "CTF.LBES.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
            "CTF.Compart.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
            "CTF.Asm.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
            "CTF.Layouts.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
            "CTF.TMD.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
            "CTF.TimListCache.FMPDefaultS-1-5-21-1482476501-1645522239-1417001333-500MUTEX.DefaultS-1-5-21-1482476501-1645522239-1417001333-500",
            "MSCTF.Shared.MUTEX.EBH"
        ],
        "mutexes_opened": [
            "ShimCacheMutex"
        ],
        "processes_terminated": [
            "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\EB93A6\\996E.exe"
        ],
        "processes_tree": [
            {
                "name": "****.exe",
                "process_id": "1036"
            },
            {
                "name": "9f9e74241d59eccfe7040bfdcbbceacb374eda397cc53a4197b59e4f6f380a91.exe",
                "process_id": "2340"
            }
        ],
        "registry_keys_opened": [
            "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\996E.exe",
            "\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\SafeBoot\\Option",
            "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\TransparentEnabled",
            "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
            "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\COMCTL32.dll",
            "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SHELL32.dll",
            "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\comdlg32.dll",
            "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WINMM.dll",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave1",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave2",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave3",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave4",
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave5"
        ],
        "tags": [
            "DIRECT_CPU_CLOCK_ACCESS",
            "RUNTIME_MODULES"
        ],
        "text_highlighted": [
            "&Open",
            "&Cancel",
            "&About",
            "Cate&gory:",
            "Host &Name (or IP address)",
            "&Port",
            "22",
            "Connection type:",
            "Ra&w",
            "&Telnet",
            "Rlog&in"
        ]
    }
}
Metadata
id
string
required
SHA-256, SHA-1 or MD5 identifying the file

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.fileAllBehavioursSummary({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get a summary of all MITRE ATT&CK techniques observed in a file
get
https://www.virustotal.com/api/v3/files/{id}/behaviour_mitre_trees
This endpoint returns a summary of MITRE ATT&CK tactics and techniques observed in each of the sandbox reports of a file.

The resulting structure is the following one:

JSON

{
  sandbox_name: {
    "tactics": [
      {
        "id": tactic_id,
        "name": tactic_name,
        "description": tactic_description,
        "link": tactic_mitre_url,
        "techniques": [
          {
            "id": technique_id,
            "name": technique_name,
            "description": technique_description,
            "link": technique_mitre_url,
            "signatures": [
              {
                "severity": severity ("HIGH" / "MEDIUM" / "LOW" / "INFO" / "UNKNOWN"),
                "description": signature_description
              }, ...
            ]
          }, ...
        ]
      }, ...
    ]
  }, ...  
}
Example response

{
	"data": {
		"VirusTotal Observer": {
			"tactics": []
		},
		"Zenbox": {
			"tactics": [
				{
					"description": "The adversary is trying to figure out your environment.\n\nDiscovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what’s around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective. ",
					"techniques": [
						{
							"description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.\nTools such as Systeminfo can be used to gather detailed system information. If running with privileged access, a breakdown of system data can be gathered through the systemsetup configuration tool on macOS. As an example, adversaries with user-level access can execute the df -aH command to obtain currently mounted disks and associated freely available space. Adversaries may also leverage a Network Device CLI on network devices to gather detailed system information. System Information Discovery combined with information gathered from other forms of discovery and reconnaissance can drive payload development and concealment.\nInfrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.",
							"signatures": [
								{
									"severity": "INFO",
									"description": "Reads software policies"
								}
							],
							"link": "https://attack.mitre.org/techniques/T1082/",
							"id": "T1082",
							"name": "System Information Discovery"
						},
						{
							"description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.\nMany command shell utilities can be used to obtain this information. Examples include dir, tree, ls, find, and locate. Custom tools may also be used to gather file and directory information and interact with the Native API. Adversaries may also leverage a Network Device CLI on network devices to gather file and directory information.",
							"signatures": [
								{
									"severity": "INFO",
									"description": "Reads ini files"
								}
							],
							"link": "https://attack.mitre.org/techniques/T1083/",
							"id": "T1083",
							"name": "File and Directory Discovery"
						}
					],
					"link": "https://attack.mitre.org/tactics/TA0007/",
					"id": "TA0007",
					"name": "Discovery"
				},
				{
					"description": "The adversary is trying to avoid being detected.\n\nDefense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses. ",
					"techniques": [
						{
							"description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. \nThere are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. \nMore sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel. ",
							"signatures": [
								{
									"severity": "INFO",
									"description": "Spawns processes"
								}
							],
							"link": "https://attack.mitre.org/techniques/T1055/",
							"id": "T1055",
							"name": "Process Injection"
						},
						{
							"description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.\nRenaming abusable system utilities to evade security monitoring is also a form of Masquerading.",
							"signatures": [
								{
									"severity": "INFO",
									"description": "Creates files inside the user directory"
								}
							],
							"link": "https://attack.mitre.org/techniques/T1036/",
							"id": "T1036",
							"name": "Masquerading"
						},
						{
							"description": "Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary (ex: Ingress Tool Transfer) may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.\nThere are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples of built-in Command and Scripting Interpreter functions include del on Windows and rm or unlink on Linux and macOS.",
							"signatures": [
								{
									"severity": "INFO",
									"description": "Deletes files inside the Windows folder"
								}
							],
							"link": "https://attack.mitre.org/techniques/T1070/004/",
							"id": "T1070.004",
							"name": "File Deletion"
						}
					],
					"link": "https://attack.mitre.org/tactics/TA0005/",
					"id": "TA0005",
					"name": "Defense Evasion"
				},
				{
					"description": "The adversary is trying to gain higher-level permissions.\n\nPrivilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include: \n\n* SYSTEM/root level\n* local administrator\n* user account with admin-like access \n* user accounts with access to specific system or perform specific function\n\nThese techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.  ",
					"techniques": [
						{
							"description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. \nThere are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. \nMore sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel. ",
							"signatures": [
								{
									"severity": "INFO",
									"description": "Spawns processes"
								}
							],
							"link": "https://attack.mitre.org/techniques/T1055/",
							"id": "T1055",
							"name": "Process Injection"
						}
					],
					"link": "https://attack.mitre.org/tactics/TA0004/",
					"id": "TA0004",
					"name": "Privilege Escalation"
				}
			]
		},
		"VirusTotal Jujubox": {
			"tactics": []
		}
	},
	"links": {
		"self": "https://www.virustotal.com/api/v3/files/bb04b55bc87b4bb4d2543bf50ff46ec840d653ca9311e9b40d9933e484719a91/behaviour_mitre_trees"
	}
}
Metadata
id
string
required
SHA-256, SHA-1 or MD5 identifying the file

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.getASummaryOfAllMitreAttckTechniquesObservedInAFile({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get all behavior reports for a file
get
https://www.virustotal.com/api/v3/files/{id}/behaviours
This endpoint returns behavioural information from each sandbox about the file.

This API call returns all fields contained in the File behaviour object.

Note some of the entries have

has_html_report if true you may fech the HTML File behaviour.
has_pcap if true you may fech the PCAP File behaviour.

Metadata
id
string
required
SHA-256, SHA-1 or MD5 identifying the file

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.getAllBehaviorReportsForAFile({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get objects related to a behaviour report
get
https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/{relationship}
As mentioned in the Relationships section, those related objects can be retrieved by sending GET requests to the relationship URL.

Available relationships are described in the File behaviour object documentation.

Metadata
sandbox_id
string
required
Sandbox report ID

relationship
string
required
Relationship name (see table)

limit
int32
Defaults to 10
Maximum number of related objects to retrieve

10
cursor
string
Continuation cursor

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.file_behaviourssandbox_idrelationship({limit: '10', sandbox_id: 'sandbox_id', relationship: 'relationship'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get a detailed HTML behaviour report
get
https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/html
HTML sandbox report

Returns a File behaviour object as an HTML report.

Sandbox Report identifiers
A Sandbox report ID has two main components: the analysed file's SHA256 and the sandbox name. These two components are joined by a _ character. For example, ID 5353e23f3653402339c93a8565307c6308ff378e03fcf23a4378f31c434030b0_VirusTotal Jujubox fetches the sandbox report for a file having a SHA256 5353e23f3653402339c93a8565307c6308ff378e03fcf23a4378f31c434030b0 analysed in the VirusTotal Jujubox sandbox.

Metadata
sandbox_id
string
required
Sandbox report ID.

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.getFileBehaviourHtml({sandbox_id: 'sandbox_id', accept: 'text/plain'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get a URL / file analysis
get
https://www.virustotal.com/api/v3/analyses/{id}
Returns an Analysis object.

Metadata
id
string
required
Analysis identifier

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.analysis({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get a submission object
get
https://www.virustotal.com/api/v3/submission/{id}
Returns a Submission object.

Metadata
id
string
required
Submission object ID

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.getSubmission({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get an operation object
get
https://www.virustotal.com/api/v3/operations/{id}
Returns an Operation object.

Metadata
id
string
required
Operation ID

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.getOperationsId({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get an attack tactic object
get
https://www.virustotal.com/api/v3/attack_tactics/{id}
Metadata
id
string
required
Attack tactic's ID

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.attack_tacticsid({id: 'id'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get objects related to an attack tactic
get
https://www.virustotal.com/api/v3/attack_tactics/{id}/{relationship}
Available relationships are described in the Attack Tactic object documentation.

Metadata
id
string
required
Attack tactic's ID

relationship
string
required
Relationship name (see table)

limit
int32
Defaults to 10
Maximum number of related objects to retrieve

10
cursor
string
Continuation cursor

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.attack_tacticsidrelationship({limit: '10', id: 'id', relationship: 'relationship'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get object descriptors related to an attack tactic
get
https://www.virustotal.com/api/v3/attack_tactics/{id}/relationships/{relationship}
This endpoint is the same as /attack_tactics/{id}/{relationship} except it returns just the related object's descriptor instead of returning all attributes.

Metadata
id
string
required
Attack tactic's ID

relationship
string
required
Relationship name (see table)

limit
int32
Defaults to 10
Maximum number of related objects to retrieve

10
cursor
string
Continuation cursor

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.attack_tacticsidrelationshipsrelationship({limit: '10', id: 'id', relationship: 'relationship'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get an attack technique object
get
https://www.virustotal.com/api/v3/attack_techniques/{id}
Metadata
id
string
required
Attack technique's ID

x-apikey
string
required
Your API key

Responses

200
200


400
400

Get objects related to an attack technique
get
https://www.virustotal.com/api/v3/attack_techniques/{id}/{relationship}
Available relationships are described in the Attack Technique object documentation.

Metadata
id
string
required
Attack technique's ID

relationship
string
required
Relationship name (see table)

limit
int32
Defaults to 10
Maximum number of related objects to retrieve

10
cursor
string
Continuation cursor

x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.attack_techniqueidrelationship({limit: '10', id: 'id', relationship: 'relationship'})
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));

  Get a list of popular threat categories
get
https://www.virustotal.com/api/v3/popular_threat_categories
Metadata
x-apikey
string
required
Your API key

Responses

200
200


400
400

import virustotal from '@api/virustotal';

virustotal.popular_threat_categories()
  .then(({ data }) => console.log(data))
  .catch(err => console.error(err));