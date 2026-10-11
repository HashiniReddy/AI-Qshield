
from pathlib import Path
import cv2

dataset = Path("dataset")
original_path = dataset / "test_qr.png"

image = cv2.imread(str(original_path))

if image is None:
    raise FileNotFoundError(f"Could not read {original_path}")

# Create a clean copy.
cv2.imwrite(str(dataset / "test_qr_clean.png"), image)

# Create a blurred version.
blurred = cv2.GaussianBlur(image, (9, 9), 0)
cv2.imwrite(str(dataset / "test_qr_blurred.png"), blurred)

# Crop 20% from the bottom and right sides.
height, width = image.shape[:2]
cropped = image[:int(height * 0.8), :int(width * 0.8)]
cv2.imwrite(str(dataset / "test_qr_cropped.png"), cropped)

print("Test images created successfully.")
print("Original dimensions:", image.shape)
print("Blurred dimensions:", blurred.shape)
print("Cropped dimensions:", cropped.shape)

