# CloudGuard CSPM - gcp-sourceimage-tagger

This script is designed to be run within GCP to receive a disk entity model in JSON format. It will iterate back through all of the source[image|disk|snapshot] entries to try and find the original source of the asset and add this data to the entity as a label (tag). 

## Usage

Install this as a GCP Cloud Function and make a note of the URL for the function. Configure it with or without authentication (whichever you require - but authentication might require additional code) and make sure the function has IAM permissions to update the labels on the entities required. 
Then create a GSL rule in CSPM that checks for the presence of cloudguard_source_image_creation_timestamp as a label key value on a GCP Disk and that the value of it falls within a specific time range. 

Eg:

```
Disk should not have tags contain [key = 'cloudguard_source_image_creation_timestamp' and value before(-45,'days')
```

Assosciate this rule with a Continuous Posture notification that calls the URL for the GCP function.

