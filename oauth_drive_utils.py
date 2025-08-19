import os
import io
import pickle
import mimetypes
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from google.auth.transport.requests import Request


SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
CLIENT_SECRET_FILE = 'client_secret.json'
TOKEN_FILE = 'token.json'

def get_credentials():
    creds = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=8080)
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
    return creds

def extract_folder_id(drive_url_or_id):
    if "folders/" in drive_url_or_id:
        return drive_url_or_id.split("folders/")[1].split("?")[0]
    return drive_url_or_id.strip()

def fetch_images_from_drive(folder_id, download_dir):
    creds = get_credentials()
    service = build('drive', 'v3', credentials=creds)

    os.makedirs(download_dir, exist_ok=True)

    query = f"'{folder_id}' in parents and mimeType contains 'image/' and trashed = false"
    results = service.files().list(q=query, fields="files(id, name)").execute()
    items = results.get('files', [])

    image_info = []

    for file in items:
        file_id = file['id']
        filename = file['name']
        request = service.files().get_media(fileId=file_id)
        fh = io.FileIO(os.path.join(download_dir, filename), 'wb')
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()

        image_info.append({
            'name': filename,
            'download_link': f"https://drive.google.com/uc?export=download&id={file_id}"
        })

    return image_info
