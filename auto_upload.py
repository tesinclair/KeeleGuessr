#! usr/bin/python3

import requests, sys, os, piexif, getpass
from PIL import Image
from dotenv import dotenv_values

conf = dotenv_values("auto_upload.env")

def get_exif_data(image_path):
    img = Image.open(image_path)
    exif_dict = piexif.load(img.info.get('exif', b''))  # Load EXIF data
    gps_data = exif_dict.get("GPS", {})
    
    if not gps_data:
        return None  # No GPS info
    
    # Convert GPS coordinates to decimal
    def _convert_to_degrees(value):
        d, m, s = value
        return float(d[0]) / d[1] + float(m[0]) / m[1] / 60 + float(s[0]) / s[1] / 3600

    # Extract GPS tags
    lat = _convert_to_degrees(gps_data.get(piexif.GPSIFD.GPSLatitude))
    lat_ref = gps_data.get(piexif.GPSIFD.GPSLatitudeRef).decode()
    if lat_ref != 'N':
        lat = -lat

    lng = _convert_to_degrees(gps_data.get(piexif.GPSIFD.GPSLongitude))
    lng_ref = gps_data.get(piexif.GPSIFD.GPSLongitudeRef).decode()
    if lng_ref != 'E':
        lng = -lng

    return lat, lng


locations = ["KEELE", "ELSTEAD"]
difficulties = ["EASY", "MEDIUM", "HARD", "HARDER", "HARDEST", "IMPOSSIBLE"]

dev = True if (conf.get('dev') or input("Development? (y): ")) == "y" else False
folder_path = os.path.expanduser(
    conf.get('folder_path') or input("Path from home (~): ")
)
difficulty = (conf.get('difficulty') or input("Difficulty: ")).upper()
location   = (conf.get('location')   or input("Location: ")).upper()
username = conf.get('username') or input("Admin Username: ")
password = conf.get('password') or getpass.getpass("Admin Password: ")

if difficulty not in difficulties or location not in locations:
    print("Difficulty or Location wrong...")
    sys.exit(1)

if dev in [True, "True", 1, "1"]:
    url = "http://keeleguesser.local:5000/admin/autoupload"
else:
    url = "https://keeleguesser.beer/admin/autoupload"

for filename in os.listdir(folder_path):
    file_path = os.path.join(folder_path, filename)
    if not os.path.isfile(file_path) or filename.split(".")[-1] not in ["jpg", "jpeg"]:
        continue

    coords = get_exif_data(file_path)
    if not coords:
        print(f"WARNING: No GPS data in {filename}, skipping...")
        continue

    lat, lng = coords

    data = {
            "username": username,
            "password": password,
            "lat": lat,
            "lng": lng,
            "difficulty": difficulty,
            "location": location
    }

    with open(file_path, "rb") as f:
        file = {"image": f}
        res = requests.post(url, data=data, files=file, verify=(not dev))

    if res.status_code == 200:
        print(f"SUCCESS: Image: {filename} uploaded Successfully")
    elif res.status_code == 401:
        print(f"ERROR: Admin failed verification!")
        print(res.text)
        sys.exit(1)
    else:
        print(f"ERROR: Image: {filename} failed to upload.")
        print(res.text)



