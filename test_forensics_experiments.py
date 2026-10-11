
import cv2
from pprint import pprint

from src.qr_engine.qr_decoder import QRDecoder
from src.qr_forensics.finder_analysis import analyze_finder_regions

decoder = QRDecoder()

image_names = [
    "test_qr_clean.png",
    "test_qr_blurred.png",
    "test_qr_cropped.png",
]

for name in image_names:
    path = f"dataset/{name}"
    image = cv2.imread(path)

    print("\n" + "=" * 45)
    print("Testing:", name)

    if image is None:
        print("Could not load image.")
        continue

    result = decoder.decode(path)

    print("Decoded successfully:", result["success"])
    print("Content:", result["content"])
    print("Geometry:")
    pprint(result["geometry"])

    _, points, _ = decoder.detector.detectAndDecode(image)

    forensic_result = analyze_finder_regions(image, points)

    print("Finder-region analysis:")
    pprint(forensic_result)
