
import cv2


def analyze_finder_regions(image, points):
    """
    Measure dark-pixel density near the three expected
    QR finder-pattern corners.

    This is a heuristic, not a definitive pattern detector.
    """

    if image is None or points is None:
        return {
            "success": False,
            "error": "Image or QR corner points unavailable",
            "regions": {}
        }

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # OpenCV normally returns four QR corner points.
    corners = points[0]

    top_left = corners[0]
    top_right = corners[1]
    bottom_left = corners[3]

    # Estimate the QR bounding-box dimensions.
    width = max(1, int(max(corners[:, 0]) - min(corners[:, 0])))
    height = max(1, int(max(corners[:, 1]) - min(corners[:, 1])))

    # Use approximately one quarter of the QR dimensions.
    region_width = max(1, width // 4)
    region_height = max(1, height // 4)

    image_height, image_width = gray.shape

    candidate_corners = {
        "top_left": top_left,
        "top_right": top_right,
        "bottom_left": bottom_left
    }

    regions = {}

    for name, corner in candidate_corners.items():
        x = int(corner[0])
        y = int(corner[1])

        if name == "top_left":
            x1, x2 = x, x + region_width
            y1, y2 = y, y + region_height

        elif name == "top_right":
            x1, x2 = x - region_width, x
            y1, y2 = y, y + region_height

        else:
            x1, x2 = x, x + region_width
            y1, y2 = y - region_height, y

        # Keep the crop within image boundaries.
        x1 = max(0, min(x1, image_width))
        x2 = max(0, min(x2, image_width))
        y1 = max(0, min(y1, image_height))
        y2 = max(0, min(y2, image_height))

        crop = gray[y1:y2, x1:x2]

        if crop.size == 0:
            regions[name] = {
                "dark_pixel_density": None,
                "error": "Empty candidate region"
            }
            continue

        dark_pixels = int((crop < 128).sum())
        total_pixels = int(crop.size)

        regions[name] = {
            "dark_pixel_density": round(
                dark_pixels / total_pixels, 3
            ),
            "region_width": int(crop.shape[1]),
            "region_height": int(crop.shape[0])
        }

    return {
        "success": True,
        "error": None,
        "regions": regions
    }
