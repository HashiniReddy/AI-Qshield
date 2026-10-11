
import cv2
from pprint import pprint

from src.qr_engine.qr_decoder import QRDecoder
from src.qr_forensics.finder_analysis import analyze_finder_regions


def main():
    image_path = "dataset/test_qr.png"

    decoder = QRDecoder()
    result = decoder.decode(image_path)

    print()
    print("=" * 50)
    print("       AI-QShield QR Intelligence Engine")
    print("=" * 50)

    print(f"Success      : {result['success']}")
    print(f"Content      : {result['content']}")
    print(f"Content Type : {result['content_type']}")
    print(f"Is URL       : {result['is_url']}")
    print(f"Error        : {result['error']}")

    print("\nQR Geometry:")
    pprint(result["geometry"])

    if not result["success"]:
        print("\nForensics skipped: QR decoding failed.")
        return

    image = cv2.imread(image_path)

    if image is None:
        print("\nForensics skipped: image could not be loaded.")
        return

    _, points, _ = decoder.detector.detectAndDecode(image)

    forensic_result = analyze_finder_regions(image, points)

    print("\nFinder Region Analysis:")
    pprint(forensic_result)

    print("=" * 50)


if __name__ == "__main__":
    main()
