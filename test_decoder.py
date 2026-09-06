from src.qr_engine.qr_decoder import QRDecoder


def main():

    decoder = QRDecoder()

    result = decoder.decode("dataset/test_qr.png")

    print()
    print("=" * 50)
    print("       AI-QShield QR Intelligence Engine")
    print("=" * 50)

    print(f"Success      : {result['success']}")
    print(f"Content      : {result['content']}")
    print(f"Content Type : {result['content_type']}")
    print(f"Is URL       : {result['is_url']}")
    print(f"Error        : {result['error']}")

    print("=" * 50)


if __name__ == "__main__":
    main()