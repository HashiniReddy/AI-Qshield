
import cv2

from src.qr_engine.qr_decoder import QRDecoder
from src.qr_forensics.finder_analysis import analyze_finder_regions

decoder = QRDecoder()

images = [
    "test_qr_clean.png",
    "test_qr_blurred.png",
    "test_qr_cropped.png",
]

print("\nAI-QShield Forensics Report")
print("=" * 65)

for filename in images:
    path = f"dataset/{filename}"
    image = cv2.imread(path)

    print(f"\nImage: {filename}")

    if image is None:
        print("Status: Image could not be loaded")
        continue

    result = decoder.decode(path)

    print("Decoded:", result["success"])

    geometry = result["geometry"]
    if geometry:
        print("Margin difference:", round(geometry["margin_difference"], 2))
        print("Margins consistent:", geometry["quiet_zone_consistent"])
    else:
        print("Geometry: Unavailable")

    _, points, _ = decoder.detector.detectAndDecode(image)
    forensic = analyze_finder_regions(image, points)

    if forensic["success"]:
        densities = {
            name: details["dark_pixel_density"]
            for name, details in forensic["regions"].items()
        }
        print("Finder-region densities:", densities)
    else:
        print("Finder analysis:", forensic["error"])

print("\n" + "=" * 65)
print("Report complete.")
