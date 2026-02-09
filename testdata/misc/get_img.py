import os
import requests

# Dictionary of external URLs and their new local filenames
apple_images = {
    "https://photos5.appleinsider.com/gallery/35159-64318-000-lead-Apple-founders-xl.jpg": "apple_founders.jpg",
    "https://upload.wikimedia.org/wikipedia/commons/7/7e/Apple_II_IMG_4212.jpg": "apple_ii.jpg",
    "https://photos5.appleinsider.com/gallery/35159-93290-000-lead-Steve-Jobs-xl.jpg": "mac_128k_jobs.jpg",
    "https://allaboutstevejobs.com/blog/wp-content/uploads/2010/09/1985-Newsweek.jpg": "jobs_newsweek_1985.jpg",
    "https://photos5.appleinsider.com/gallery/34457-62162-merger122111-xl.jpg": "apple_next_merger.jpg",
    "https://mydesignlife.com/dev/wp-content/uploads/2014/06/iMac-1024x704.png": "imac_g3_bondi.png",
    "https://upload.wikimedia.org/wikipedia/en/d/d8/MacOSX10-0screenshot.png": "macosx_cheetah.png",
    "https://i0.wp.com/macdailynews.com/wp-content/uploads/2014/01/140117_steve_jobs_intel.jpg?w=550&ssl=1": "intel_transition.jpg",
    "https://nypost.com/wp-content/uploads/sites/2/2023/01/newspress-collage-25288920-1673246153542.jpg": "iphone_launch.jpg",
    "https://www.cultofmac.com/wp-content/uploads/2016/10/maxresdefault.jpg": "icloud_launch.jpg",
    "https://www.apple.com/newsroom/images/product/mac/standard/Apple_new-m1-chip-graphic_11102020_big.jpg.large.jpg": "apple_m1_chip.jpg"
}

os.makedirs('images', exist_ok=True)

headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

print("Starting Apple Image Sync...")

for url, filename in apple_images.items():
    try:
        response = requests.get(url, headers=headers, stream=True, timeout=15)
        if response.status_code == 200:
            with open(f"images/{filename}", 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            print(f"✅ Saved: {filename}")
        else:
            print(f"❌ Failed: {filename} (HTTP {response.status_code})")
    except Exception as e:
        print(f"⚠️ Error with {filename}: {e}")

print("\nApple images synced to /images folder.")
