# Name: GCP Image source tagger
# Description: Images / disks / snapshots in GCP have a property of 'image creation date'. 
#  This refers to when the disk / virtual machine was created, but not necessarily the
#  the creation date of the original image from which snapshots etc. were created.
#  Example: If you create a disk from an image which is 10 years old - that won't be reflected
#  in the image creation date timestamp of the disk. 
#
#  This script will iterate back through the various source* IDs until it can't go any further
#  to find the earliest existing source image and log that as a label.
#
# Usage: This script is designed to receive a JSON formatted payload from CloudGuard CSPM containing details
#  about the entity. It be run as a Cloud Function, triggered by a Continuous Posture notification to the webhook URL for
#  the function. 
# Stuart Green - Check Point. 19/5/2021. 

import json
import time
from flask import Response
import googleapiclient.discovery

# Prepare the received entity and return the relevant values as a dict
def process_cspm_entity(cspm_entity):
  asset = {}
  asset['zone'] = cspm_entity['entity']['zone'].split('/')[-1]
  asset['project'] = cspm_entity['account']['id']
  asset['original_name'] = cspm_entity['entity']['name']
  # There appear to be three source types, disk, image and snapshot.
  # Parse and then add the type to the dict

  if "sourceImage" in cspm_entity['entity']:
    # Get source including project
    asset['source'] = "/".join(cspm_entity['entity']['sourceImage'].split('/')[7:])
    asset['type'] = "image"
    asset['name'] = asset['source'].split('/')[-1]
    # Get project name from URL (selflink?)
    asset['asset_proj'] = cspm_entity['entity']['sourceImage'].split('/')[6]
    return asset
  elif "sourceSnapshot" in cspm_entity['entity']:
    asset['source'] = "/".join(cspm_entity['entity']['sourceSnapshot'].split('/')[7:])
    asset['type'] = "snapshot"
    asset['asset_proj'] = cspm_entity['entity']['sourceSnapshot'].split('/')[6]
    asset['name'] = asset['source'].split('/')[-1]
    return asset
  elif "sourceDisk" in cspm_entity['entity']:
    asset['source'] = "/".join(cspm_entity['entity']['sourceDisk'].split('/')[7:])
    asset['type'] = "disk"
    asset['asset_proj'] = cspm_entity['entity']['sourceDisk'].split('/')[6]
    asset['name'] = asset['source'].split('/')[-1]
    return asset
  else:
    asset = None
    return asset

def process_google_entity(google_entity):
  asset = {}

  # Each source type is treated slightly differently by the GCP API
  # So determine the type and use this later for API calls into GCP
  if 'sourceImage' in google_entity:
    asset['source'] = "/".join(google_entity['sourceImage'].split('/')[7:])
    asset['type'] = "image"
    asset['name'] = asset['source'].split('/')[-1]
    asset['asset_proj'] = google_entity['sourceImage'].split('/')[6]
    return asset
  elif 'sourceSnapshot' in google_entity:
    asset['source'] = "/".join(google_entity['sourceSnapshot'].split('/')[7:])
    asset['type'] = "snapshot"
    asset['name'] = asset['source'].split('/')[-1]
    asset['asset_proj'] = google_entity['sourceDisk'].split('/')[6]
    return asset
  elif 'sourceDisk' in google_entity:
    asset['source'] = "/".join(google_entity['sourceDisk'].split('/')[7:])
    asset['type'] = "disk"
    asset['name'] = asset['source'].split('/')[-1]
    asset['asset_proj'] = google_entity['sourceDisk'].split('/')[6]
    asset['zone'] = google_entity['sourceDisk'].split('/')[8]
    return asset
  else:
    asset = None
    return asset
# request is a Flask class of input from the GCP Cloud Function Python handler

def process_incoming(request):

  request_json = request.get_json()
  asset = process_cspm_entity(request_json)
  # Retrive GCP info on origianl asset
  compute = googleapiclient.discovery.build('compute', 'v1')

  # Could break this section out into a function, but we only do this once outside of the main loop
  if asset['type'] == "disk":
    g_asset_info = compute.disks().get(zone=asset['zone'], project=asset['asset_proj'], disk=asset['name']).execute()
  elif asset['type'] == "image":
    g_asset_info = compute.images().get(project=asset['asset_proj'], image=asset['name']).execute()
  elif asset['type'] == "snapshot":
    g_asset_info = compute.snapshots().get(project=asset['asset_proj'], snapshot=asset['name']).execute()
  else:
    # Unknown asset type
    exit()

  # While one of the loop_triggers is present in the response, keep going.
  # Usually sourcetype = RAW is a sign you've gotten to the actual source but not tested extensively.
  loop_triggers = ['sourceSnapshot', 'sourceDisk', 'sourceImage']
  while any(key in g_asset_info for key in loop_triggers):
    g_asset_parsed = process_google_entity(g_asset_info)
    if 'sourceDisk' in g_asset_info:
      g_asset_info = compute.disks().get(zone=g_asset_parsed['zone'], project=g_asset_parsed['asset_proj'], disk=g_asset_parsed['name']).execute()
      continue
    if 'sourceImage' in g_asset_info:
      g_asset_old = g_asset_info
      # Try / except here because some source projects are not available for listing - we'll assume this is the furthest
      # back we can get
      try:
        g_asset_info = compute.images().get(project=g_asset_parsed['asset_proj'], image=g_asset_parsed['name']).execute()
      except googleapiclient.discovery.HttpError as gErr:
        if gErr.args[0].status == 403:
          # Auth error on Google side - can't resolve earlier sources
          # restore last object
          g_asset_info = g_asset_old
        break
      continue
    if 'sourceSnapshot' in g_asset_info:
      g_asset_info = compute.snapshots().get(project=g_asset_parsed['asset_proj'], snapshot=g_asset_parsed['name']).execute()
      continue

  # Build request body for tagging / labelling resource  


  # Time pattern from GCP API
  time_pattern = '%Y-%m-%dT%H:%M:%S.%f%z'
  # Change image source timestamp back to epoch
  creation_timestamp_epoch = time.mktime(time.strptime(g_asset_info['creationTimestamp'], time_pattern))

  entity_label_body = {}
  entity_label_body['labels'] = {}
  entity_label_body['labels']['cloudguard_source_image_creation_timestamp'] = creation_timestamp_epoch
  entity_label_body['labels']['cloudguard_source_image_name'] = g_asset_info['name']
  entity_label_body['labels']['cloudguard_source_image_project'] = g_asset_info['selfLink'].split('/')[6]
  entity_label_body['labelFingerprint'] = request_json['entity']['labelFingerprint']
  # Add deprecated tag - might be useful to have
  if "deprecated" in g_asset_info:
    entity_label_body['labels']['deprecated_source']='deprecated' 
  # Apply tag to disk
  tag = compute.disks().setLabels(project=asset['project'], zone=asset['zone'], resource=asset['original_name'], body=entity_label_body).execute()