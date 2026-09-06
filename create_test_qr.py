import qrcode
from pathlib import Path

# Create dataset directory if it doesn't exist
dataset_dir = Path("dataset")
dataset_dir.mkdir(exist_ok=True)

# Harmless test URL
url = "https://example.com"

# Generate QR code
qr = qrcode.QRCode(
    version=1,
    box_size=10,
    border=4
)

qr.add_data(url)
qr.make(fit=True)

img = qr.make_image()

# Save QR image
output_path = dataset_dir / "test_qr.png"
img.save(output_path)

print(f"QR code created: {output_path}")
print(f"Encoded content: {url}")