
def check_qr_points(points):
    """
    Check whether OpenCV detected QR corner points.
    """

    if points is None:
        return {
            "detected": False,
            "message": "QR corner points not available"
        }

    points = points[0]

    return {
        "detected": True,
        "message": "QR corner points available",
        "corner_count": len(points)
    }
