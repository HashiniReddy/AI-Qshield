
from pathlib import Path

import cv2

from src.qr_forensics.image_quality import analyze_image_quality


image_paths = [
    Path("dataset/test_qr_clean.png"),
    Path("dataset/test_qr_blurred.png"),
    Path("dataset/test_qr_cropped.png"),
]

print("AI-QShield — Image Quality Comparison")
print("=" * 45)

for image_path in image_paths:
    image = cv2.imread(str(image_path))

    if image is None:
        print(f"\n{image_path.name}: Image not found")
        continue

    result = analyze_image_quality(image)

    print(f"\nImage: {image_path.name}")

    if not result["success"]:
        print(f"Error: {result['error']}")
        continue

    print(f"Dimensions: {result['width']} x {result['height']}")
    print(f"Sharpness: {result['sharpness_score']}")
    print(f"Contrast: {result['contrast_score']}")
